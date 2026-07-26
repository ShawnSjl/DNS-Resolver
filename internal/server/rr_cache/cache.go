package rr_cache

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	MaxTTL = 60 * 60 * 24 * 7 // maximum TTL in seconds, 7 days
)

type Cache struct {
	ctx    context.Context
	logger *slog.Logger

	rrSets map[SetKey]*WeightedRRSet
	mutex  sync.RWMutex
}

func NewCache(parent context.Context, logger *slog.Logger) *Cache {
	ctx := context.WithoutCancel(parent)

	cache := &Cache{
		ctx:    ctx,
		logger: logger.WithGroup("rr_cache"),
		rrSets: make(map[SetKey]*WeightedRRSet),
		mutex:  sync.RWMutex{},
	}

	go cache.ttlTimer()

	return cache
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

func (c *Cache) GetWeightedRRSet(rrSetKey SetKey) (*WeightedRRSet, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	set, ok := c.rrSets[rrSetKey]

	if ok {
		slog.Debug("Cache hit", "domain", rrSetKey.Domain, "qType", rrSetKey.QType)
	} else {
		slog.Debug("Cache miss", "domain", rrSetKey.Domain, "qType", rrSetKey.QType)
	}

	return set, ok
}

func (c *Cache) AddRR(rr dns.RR, limitTTL bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	setKey := SetKey{
		Domain: rr.Header().Name,
		QType:  rr.Header().Rrtype,
		QClass: rr.Header().Class,
	}

	// Limit TTL to 7 days
	if limitTTL {
		rr.Header().Ttl = min(rr.Header().Ttl, MaxTTL) // limit TTL to 7 days
	}

	// Create RRSet if it doesn't exist'
	if _, ok := c.rrSets[setKey]; !ok {
		c.rrSets[setKey] = &WeightedRRSet{
			mutex: sync.RWMutex{},
			rrs:   make(map[string]*weightedRR),
		}
	}

	// Add RR to RRSet
	c.rrSets[setKey].addRR(rr)

	slog.Debug("Added RR to cache", "rr", rr.String())
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
