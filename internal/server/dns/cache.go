package dns

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	MaxTTL = 60 * 60 * 24 * 7 // maximum TTL in seconds, 7 days
)

type RecordCache struct {
	ctx context.Context

	records map[CacheKey]dns.RR
	mutex   sync.RWMutex
}

type CacheKey struct {
	domain string
	qType  uint16
	qClass uint16
}

// ******************** Initialization Interface **********************

func NewRecordCache(parent context.Context) *RecordCache {
	// Create a child context without cancellation
	ctx := context.WithoutCancel(parent)

	cache := &RecordCache{
		ctx:     ctx,
		records: make(map[CacheKey]dns.RR),
		mutex:   sync.RWMutex{},
	}

	// Start TTL timer
	cache.StartTTLTimer()

	return cache
}

// ******************** TTL Timer **********************

func (c *RecordCache) StartTTLTimer() {
	go func() {
		// Start a ticker to check TTL every second
		ticker := time.NewTicker(time.Second)

		for {
			select {
			case <-c.ctx.Done():
				ticker.Stop()
				return

			case <-ticker.C:
				c.mutex.Lock()
				var deleteList []CacheKey

				// Decrement TTL every second for all records
				for key, record := range c.records {
					record.Header().Ttl--

					// Check if TTL is 0
					if record.Header().Ttl <= 0 {
						deleteList = append(deleteList, key)
					}
				}

				// Remove expired records
				for _, key := range deleteList {
					delete(c.records, key)
				}
				c.mutex.Unlock()
			}
		}
	}()
}

// ******************** Interface **********************

func (c *RecordCache) Add(rr dns.RR) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	key := CacheKey{
		domain: rr.Header().Name,
		qType:  rr.Header().Rrtype,
		qClass: rr.Header().Class,
	}

	rr.Header().Ttl = min(rr.Header().Ttl, MaxTTL) // limit TTL to 7 days
	c.records[key] = rr
}

func (c *RecordCache) Get(key CacheKey) (dns.RR, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.records[key], c.records[key] != nil
}

func (c *RecordCache) List() string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	var list []string

	for _, record := range c.records {
		list = append(list, record.String())
	}

	return strings.Join(list, "\n")
}
