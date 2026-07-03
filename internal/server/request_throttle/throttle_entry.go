package request_throttle

import (
	"context"
	"time"
)

type throttleEntry struct {
	ctx context.Context

	interval time.Duration
	timer    *time.Timer
	ch       chan struct{}
}

func newThrottleEntry(ctx context.Context, interval time.Duration) *throttleEntry {
	// check the interval
	if interval <= 0 {
		interval = defaultInterval
	} else if interval <= minimumInterval {
		interval = minimumInterval
	}

	e := &throttleEntry{
		ctx:      ctx,
		interval: interval,
		ch:       make(chan struct{}, 1),
	}
	go e.fire()
	return e
}

func (e *throttleEntry) fire() {
	e.timer = time.NewTimer(0 * time.Second)
	defer func() {
		if e.timer != nil && !e.timer.Stop() {
			select {
			case <-e.timer.C:
			default:
			}
		}
	}()

	for {
		select {
		case <-e.ctx.Done():
			return

		case <-e.timer.C:
			// send signal to the channel
			select {
			case e.ch <- struct{}{}:
			default:
			}
		}
	}
}

func (e *throttleEntry) wait() {
	// wait for the channel to get signal or the context to be canceled
	select {
	case <-e.ctx.Done():
	case <-e.ch:
		// reset the timer
		e.timer.Reset(e.interval)
	}
}
