package request_throttle

import (
	"context"
	"sync"
	"time"
)

const (
	minimumInterval = 100 * time.Millisecond
	defaultInterval = 200 * time.Millisecond
)

type RequestThrottle struct {
	ctx context.Context

	mu      sync.Mutex
	entries map[string]*throttleEntry

	interval time.Duration
}

func NewRequestThrottle(parent context.Context, interval time.Duration) *RequestThrottle {
	// check the interval
	if interval <= 0 {
		interval = defaultInterval
	} else if interval <= minimumInterval {
		interval = minimumInterval
	}

	ctx := context.WithoutCancel(parent)
	return &RequestThrottle{
		ctx:      ctx,
		mu:       sync.Mutex{},
		entries:  make(map[string]*throttleEntry),
		interval: interval,
	}
}

// Wait blocks thread until the key is accessed before the given duration
func (t *RequestThrottle) Wait(key string) {
	// Find target entry from the map
	t.mu.Lock()
	entry, ok := t.entries[key]
	if !ok {
		entry = newThrottleEntry(t.ctx, t.interval)
		t.entries[key] = entry
	}
	t.mu.Unlock()

	// Wait for the entry to be ready
	entry.wait()
}
