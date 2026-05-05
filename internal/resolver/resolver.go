package resolver

import (
	"context"
	"errors"
	"time"

	"github.com/miekg/dns"
)

var ErrNoResolvers = errors.New("no DNS resolvers configured")

type Resolver interface {
	Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

type RateLimiter struct {
	interval time.Duration
	next     time.Time
	locker   chan struct{}
}

func NewRateLimiter(interval time.Duration) *RateLimiter {
	return &RateLimiter{
		interval: interval,
		locker:   make(chan struct{}, 1),
	}
}

func (r *RateLimiter) Wait(ctx context.Context) error {
	if r == nil || r.interval <= 0 {
		return ctx.Err()
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case r.locker <- struct{}{}:
		}

		now := time.Now()
		wait := r.next.Sub(now)
		if wait <= 0 {
			r.next = now.Add(r.interval)
			<-r.locker
			return nil
		}
		<-r.locker

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
