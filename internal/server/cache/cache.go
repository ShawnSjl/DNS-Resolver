package cache

import (
	"context"
	"strings"
	"sync"
	"time"
)

type RecordCache struct {
	ctx context.Context

	records map[string]*Record
	mutex   sync.RWMutex
}

// ******************** Initialization Interface **********************

func NewRecordCache(parent context.Context) *RecordCache {
	// Create a child context without cancellation
	ctx := context.WithoutCancel(parent)

	cache := &RecordCache{
		ctx:     ctx,
		records: make(map[string]*Record),
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
		timer := time.NewTicker(time.Second)

		for {
			select {
			case <-c.ctx.Done():
				return

			case <-timer.C:
				c.mutex.Lock()
				var deleteList []string

				// Decrement TTL every second for all records
				for key, record := range c.records {
					record.TTL--

					// Check if TTL is 0
					if record.TTL <= 0 {
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

func (c *RecordCache) Get(key string) (*Record, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.records[key], c.records[key] != nil
}

func (c *RecordCache) Set(record *Record) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.records[record.Address] = record
}

func (c *RecordCache) List() string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	var list []string
	list = append(list, "Name   Type   Class    TTL   Address")

	for _, record := range c.records {
		list = append(list, record.String())
	}

	return strings.Join(list, "\n")
}
