package request_throttle

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

const (
	minimumInterval      = 100 * time.Millisecond
	defaultInterval      = 200 * time.Millisecond
	recycleCheckInterval = 30 * time.Second
	entryIdleTimeout     = 5 * time.Minute
)

var (
	globalThrottle atomic.Pointer[RequestThrottle]
	startOnce      sync.Once
)

type RequestThrottle struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	entries map[string]*throttleEntry

	interval time.Duration

	closeOnce sync.Once
}

// ******************** Global Cache Interface **********************

func StartGlobal(parent context.Context, interval time.Duration) {
	startOnce.Do(func() {
		globalThrottle.Store(NewRequestThrottle(parent, interval))
	})
}

func Global() *RequestThrottle {
	throttle := globalThrottle.Load()
	if throttle == nil {
		panic("RequestThrottle not started")
	}
	return throttle
}

// ******************** Normal Interface **********************

func NewRequestThrottle(parent context.Context, interval time.Duration) *RequestThrottle {
	if parent == nil {
		parent = context.Background()
	}

	// check the interval
	if interval <= 0 {
		interval = defaultInterval
	} else if interval <= minimumInterval {
		interval = minimumInterval
	}

	ctx, cancel := context.WithCancel(parent)

	throttle := &RequestThrottle{
		ctx:      ctx,
		cancel:   cancel,
		mu:       sync.Mutex{},
		entries:  make(map[string]*throttleEntry),
		interval: interval,
	}

	// Start recycle timer
	go throttle.recycle()
	return throttle
}

func (t *RequestThrottle) Close() {
	t.closeOnce.Do(t.cancel)
}

// Wait blocks thread until the key is accessed before the given duration
func (t *RequestThrottle) Wait(key string) {
	// Acquire the entry
	entry := t.acquireEntry(key)

	// Wait for the entry to be ready
	entry.wait()

	// Release the entry
	t.releaseEntry(entry)
}

func (t *RequestThrottle) acquireEntry(key string) *throttleEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.entries[key]
	if !ok {
		entry = newThrottleEntry(t.ctx, t.interval)
		t.entries[key] = entry
	}

	entry.waitCount++
	entry.accessTime = time.Now()
	return entry
}

func (t *RequestThrottle) releaseEntry(entry *throttleEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry.waitCount--
	entry.accessTime = time.Now()
}

// recycle removes the entries that are not accessed for a long time
func (t *RequestThrottle) recycle() {
	ticker := time.NewTicker(recycleCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.ctx.Done():
			return

		case <-ticker.C:
			expired := make([]*throttleEntry, 0)

			// Find the entries that are not accessed for a long time
			t.mu.Lock()
			now := time.Now()
			for key, entry := range t.entries {
				// Check if some queries are still in progress
				if entry.waitCount != 0 {
					continue
				}

				// Check if the entry is idle for a long time
				if now.Sub(entry.accessTime) < entryIdleTimeout {
					continue
				}

				// Remove the entry from the map
				delete(t.entries, key)
				expired = append(expired, entry)
			}
			t.mu.Unlock()

			// Cancel the expired entries
			for _, entries := range expired {
				entries.cancel()
			}
		}
	}
}
