package dns

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

type RecordCache struct {
	ctx    context.Context
	logger *slog.Logger

	records map[RRSetKey]RRSet
	mutex   sync.RWMutex
}

type RRSetKey struct {
	domain string
	qType  uint16
	qClass uint16
}

type RRSet struct {
	rrs map[string]dns.RR
}

// ******************** Initialization Interface **********************

func newRecordCache(parent context.Context, logger *slog.Logger) *RecordCache {
	// Create a child context without cancellation
	ctx := context.WithoutCancel(parent)

	cache := &RecordCache{
		ctx:     ctx,
		logger:  logger.WithGroup("cache"),
		records: make(map[RRSetKey]RRSet),
		mutex:   sync.RWMutex{},
	}

	// Start TTL timer
	cache.startTTLTimer()

	return cache
}

// ******************** TTL Timer **********************

func (c *RecordCache) startTTLTimer() {
	go func() {
		// Start a ticker to check TTL every second
		ticker := time.NewTicker(time.Second)

		for {
			select {
			case <-c.ctx.Done():
				ticker.Stop()
				return

			case <-ticker.C:
				c.logger.Debug("TTL timer fired")
				c.mutex.Lock()

				for setKey, rrSet := range c.records {
					// Decrement TTL every second for all records and collect expired records
					var deleteList []string
					for key, rr := range rrSet.rrs {
						rr.Header().Ttl--

						if rr.Header().Ttl <= 0 {
							deleteList = append(deleteList, key)
						}
					}
					// Remove expired records
					for _, key := range deleteList {
						delete(rrSet.rrs, key)
					}

					// If all records are expired, remove the RRSet
					if len(rrSet.rrs) == 0 {
						delete(c.records, setKey)
					}
				}

				c.mutex.Unlock()
			}
		}
	}()
}

// ******************** Interface **********************

func (c *RecordCache) add(rr dns.RR, limitTTL bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	key := RRSetKey{
		domain: rr.Header().Name,
		qType:  rr.Header().Rrtype,
		qClass: rr.Header().Class,
	}

	if limitTTL {
		rr.Header().Ttl = min(rr.Header().Ttl, MaxTTL) // limit TTL to 7 days
	}

	if _, ok := c.records[key]; !ok {
		c.records[key] = RRSet{rrs: make(map[string]dns.RR)}
	}

	rrSet := c.records[key]
	rrSet.add(rr)
	slog.Debug("Added RR to cache", "rr", rr.String())
}

func (s *RRSet) add(rr dns.RR) {
	s.rrs[rrDataKey(rr)] = rr
}

func rrDataKey(rr dns.RR) string {
	switch r := rr.(type) {
	case *dns.A:
		return r.A.String()
	case *dns.AAAA:
		return r.AAAA.String()
	case *dns.NS:
		return dns.Fqdn(strings.ToLower(r.Ns))
	case *dns.CNAME:
		return dns.Fqdn(strings.ToLower(r.Target))
	case *dns.MX:
		return fmt.Sprintf("%s %d", dns.Fqdn(strings.ToLower(r.Mx)), r.Preference)
	default:
		return rr.String()
	}
}

func (c *RecordCache) get(domain string, qType uint16, qClass uint16) ([]dns.RR, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	key := RRSetKey{
		domain: domain,
		qType:  qType,
		qClass: qClass,
	}

	// Check if the RRSet exists
	if rrSet, ok := c.records[key]; ok {
		// Return a copy of the RRSet
		rrs := make([]dns.RR, 0, len(rrSet.rrs))
		for _, rr := range rrSet.rrs {
			r := dns.Copy(rr)
			r.Header().Ttl = min(r.Header().Ttl, MaxTTL)
			rrs = append(rrs, r)
		}
		slog.Debug("Cache hit", "domain", domain, "qType", qType, "rrs", rrs)
		return rrs, true
	}

	slog.Debug("Cache miss", "domain", domain, "qType", qType)
	return nil, false
}

func (c *RecordCache) toString() string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	var list []string

	for rrSetKey, rrSet := range c.records {
		list = append(list, fmt.Sprintf("RRSet: %s %d %d", rrSetKey.domain, rrSetKey.qType, rrSetKey.qClass))
		for _, rr := range rrSet.rrs {
			list = append(list, rr.String())
		}
	}

	return strings.Join(list, "\n")
}

func (c *RecordCache) dump() {
	fmt.Println(c.toString())
}
