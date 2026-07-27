package request_throttle

import (
	"context"
	"time"
)

type throttleEntry struct {
	ctx    context.Context
	cancel context.CancelFunc

	interval time.Duration
	timer    *time.Timer
	ch       chan struct{}

	waitCount  int32
	accessTime time.Time
}

func newThrottleEntry(parent context.Context, interval time.Duration) *throttleEntry {
	// check the interval
	if interval <= 0 {
		interval = defaultInterval
	} else if interval <= minimumInterval {
		interval = minimumInterval
	}

	ctx, cancel := context.WithCancel(parent)
	e := &throttleEntry{
		ctx:        ctx,
		cancel:     cancel,
		interval:   interval,
		ch:         make(chan struct{}, 1),
		waitCount:  0,
		accessTime: time.Now(),
	}

	// start the timer to signal the channel
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
