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

	rrSets    map[setKey]*WeightedRRSet       // primary cache
	nameTypes map[nameKey]map[uint16]struct{} // secondary cache for name -> qType
	mutex     sync.RWMutex

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
		ctx:       ctx,
		cancel:    cancel,
		logger:    logger,
		rrSets:    make(map[setKey]*WeightedRRSet),
		nameTypes: make(map[nameKey]map[uint16]struct{}),
		mutex:     sync.RWMutex{},
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
					// Remove RRSet from primary cache
					delete(c.rrSets, rrSetKey)

					// Remove that type from nameTypes cache
					nKey := nameKey{
						domain: rrSetKey.domain,
						qClass: rrSetKey.qClass,
					}

					types := c.nameTypes[nKey]
					delete(types, rrSetKey.qType)

					if len(types) == 0 {
						delete(c.nameTypes, nKey)
					}
				}
			}

			c.mutex.Unlock()
		}
	}
}

func (c *Cache) GetWeightedRRSet(domain string, qType uint16, qClass uint16) (*WeightedRRSet, bool) {
	// Get RRSet key
	key := setKey{
		domain: domain,
		qType:  qType,
		qClass: qClass,
	}

	// Lock cache
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	set, ok := c.rrSets[key]

	if ok {
		slog.Debug("Cache hit", "domain", key.domain, "qType", key.qType)
	} else {
		slog.Debug("Cache miss", "domain", key.domain, "qType", key.qType)
	}

	return set, ok
}

func (c *Cache) AddRR(rr dns.RR, limitTTL bool) bool {
	header := rr.Header()

	// Get RRSet key
	key := setKey{
		domain: header.Name,
		qType:  header.Rrtype,
		qClass: header.Class,
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
	if _, exist := c.rrSets[key]; !exist {
		// Create RRSet
		c.rrSets[key] = &WeightedRRSet{
			mutex: sync.RWMutex{},
			rrs:   make(map[string]*weightedRR),
		}

		// Update nameTypes cache
		if c.nameTypes == nil {
			c.nameTypes = make(map[nameKey]map[uint16]struct{})
		}
		nkey := nameKey{
			domain: key.domain,
			qClass: key.qClass,
		}
		types := c.nameTypes[nkey]
		if types == nil {
			types = make(map[uint16]struct{})
			c.nameTypes[nkey] = types
		}
		types[key.qType] = struct{}{}
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

	// Get name key
	key := nameKey{
		domain: header.Name,
		qClass: header.Class,
	}

	// Get all exists types of this domain, if empty, return true
	types := c.nameTypes[key]
	if len(types) == 0 {
		return true
	}

	// If current RR is CNAME, return true if only CNAME exists
	if header.Rrtype == dns.TypeCNAME {
		_, onlyCNAME := types[dns.TypeCNAME]
		return len(types) == 1 && onlyCNAME
	}

	// If current RR is not CNAME, return true if no CNAME exists
	_, hasCNAME := types[dns.TypeCNAME]
	return !hasCNAME
}

func (c *Cache) ToString() string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	var list []string
	for key, rrSet := range c.rrSets {
		list = append(list, fmt.Sprintf("RRSet: %s %d %d", key.domain, key.qType, key.qClass))
		for _, wRR := range rrSet.rrs {
			list = append(list, wRR.rr.String())
		}
	}

	return strings.Join(list, "\n")
}
