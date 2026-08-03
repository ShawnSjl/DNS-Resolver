package rr_cache

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	MaxTTL = 60 * 60 * 24 * 7 // maximum TTL in seconds, 7 days
)

var (
	globalCache atomic.Pointer[Cache]
	startOnce   sync.Once
)

type Cache struct {
	ctx    context.Context
	cancel context.CancelFunc
	logger *slog.Logger

	rrSets map[setKey]*WeightedRRSet
	mutex  sync.RWMutex

	closeOnce sync.Once
}

// ******************** Global Cache Interface **********************

func StartGlobal(parent context.Context, logger *slog.Logger) {
	startOnce.Do(func() {
		globalCache.Store(NewCache(parent, logger))
	})
}

func Global() *Cache {
	cache := globalCache.Load()
	if cache == nil {
		panic("Cache not started")
	}
	return cache
}

// ******************** Normal Interface **********************

func NewCache(parent context.Context, logger *slog.Logger) *Cache {
	if parent == nil {
		parent = context.Background()
	}

	if logger == nil {
		logger = slog.Default()
	}

	ctx, cancel := context.WithCancel(parent)

	cache := &Cache{
		ctx:    ctx,
		cancel: cancel,
		logger: logger.WithGroup("rr_cache"),
		rrSets: make(map[setKey]*WeightedRRSet),
		mutex:  sync.RWMutex{},
	}

	go cache.ttlTimer()

	return cache
}

func (c *Cache) Close() {
	c.closeOnce.Do(c.cancel)
}

func (c *Cache) ttlTimer() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return

		case <-ticker.C:
			c.logger.Debug("TTL timer fired")
			c.mutex.Lock()

			for rrSetKey, rrSet := range c.rrSets {
				// Decrement TTL every second for all records and collect expired records
				var deleteList []string
				for key, wRR := range rrSet.rrs {
					wRR.rr.Header().Ttl--

					if wRR.rr.Header().Ttl <= 0 {
						deleteList = append(deleteList, key)
					}
				}

				// Remove expired records
				for _, key := range deleteList {
					delete(rrSet.rrs, key)
				}

				// If all records are expired, remove the RRSet
				if len(rrSet.rrs) == 0 {
					delete(c.rrSets, rrSetKey)
				}
			}

			c.mutex.Unlock()
		}
	}
}

func (c *Cache) GetWeightedRRSet(domain string, qType uint16, qClass uint16) (*WeightedRRSet, bool) {
	// Get RRSet key
	key := setKey{
		Domain: domain,
		QType:  qType,
		QClass: qClass,
	}

	// Lock cache
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	set, ok := c.rrSets[key]

	if ok {
		slog.Debug("Cache hit", "domain", key.Domain, "qType", key.QType)
	} else {
		slog.Debug("Cache miss", "domain", key.Domain, "qType", key.QType)
	}

	return set, ok
}

func (c *Cache) AddRR(rr dns.RR, limitTTL bool) bool {
	header := rr.Header()

	// Get RRSet key
	key := setKey{
		Domain: header.Name,
		QType:  header.Rrtype,
		QClass: header.Class,
	}

	// Lock cache
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// CNAMEs can't be cached with other records in the same domain
	if !c.canAddRR(rr) {
		slog.Warn("CNAME can't be cached with other records in the same domain", "rr", rr.String())
		return false
	}

	// Limit TTL to 7 days
	if limitTTL {
		header.Ttl = min(header.Ttl, MaxTTL) // limit TTL to 7 days
	}

	// Create RRSet if it doesn't exist'
	if _, ok := c.rrSets[key]; !ok {
		c.rrSets[key] = &WeightedRRSet{
			mutex: sync.RWMutex{},
			rrs:   make(map[string]*weightedRR),
		}
	}

	// Add RR to RRSet
	c.rrSets[key].addRR(rr)
	slog.Debug("Added RR to cache", "rr", rr.String())

	return true
}

// canAddRR returns true if the RR can be added to the cache, false otherwise.
// CNAMEs can't be cached with other records in the same domain.
// Function should be called after requiring the cache lock.
func (c *Cache) canAddRR(rr dns.RR) bool {
	header := rr.Header()
	isCNAME := header.Rrtype == dns.TypeCNAME

	for key := range c.rrSets {
		if key.Domain != header.Name || key.QClass != header.Class {
			continue
		}

		existingIsCNAME := key.QType == dns.TypeCNAME

		// if one is CNAME and the other is not, return false
		if isCNAME != existingIsCNAME {
			return false
		}
	}

	return true
}

func (c *Cache) ToString() string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	var list []string
	for setKey, rrSet := range c.rrSets {
		list = append(list, fmt.Sprintf("RRSet: %s %d %d", setKey.Domain, setKey.QType, setKey.QClass))
		for _, wRR := range rrSet.rrs {
			list = append(list, wRR.rr.String())
		}
	}

	return strings.Join(list, "\n")
}
