package request_throttle

import (
	"context"
	"testing"
	"time"
)

func TestThrottleInterval_Default(t *testing.T) {
	ctx := context.Background()
	throttle := NewRequestThrottle(ctx, 0*time.Millisecond)
	if throttle.interval != defaultInterval {
		t.Fatal("expected default interval")
	}
}

func TestThrottleInterval_Minimum(t *testing.T) {
	ctx := context.Background()
	throttle := NewRequestThrottle(ctx, 1*time.Millisecond)
	if throttle.interval != minimumInterval {
		t.Fatal("expected minimum interval")
	}
}

func TestThrottleInterval_Custom(t *testing.T) {
	ctx := context.Background()
	throttle := NewRequestThrottle(ctx, 400*time.Millisecond)
	if throttle.interval != 400*time.Millisecond {
		t.Fatal("expected exact interval")
	}
}

func TestRequestThrottle_SameKeyShouldRespectInterval(t *testing.T) {
	ctx := context.Background()
	const interval = 200 * time.Millisecond

	throttle := NewRequestThrottle(ctx, interval)

	done := make(chan time.Time, 2)

	for i := 0; i < 2; i++ {
		go func() {
			throttle.Wait("same-key")
			done <- time.Now()
		}()
	}

	t1 := <-done
	t2 := <-done

	if t2.Before(t1) {
		t1, t2 = t2, t1
	}

	diff := t2.Sub(t1)
	if diff < interval {
		t.Fatalf("expected at least %v between same-key requests, got %v", interval, diff)
	}
}

func TestRequestThrottle_DifferentKeysShouldNotBlockEachOther(t *testing.T) {
	ctx := context.Background()
	const interval = 500 * time.Millisecond

	throttle := NewRequestThrottle(ctx, interval)

	keys := []string{
		"key-1",
		"key-2",
		"key-3",
		"key-4",
		"key-5",
	}

	done := make(chan struct{}, len(keys))

	start := time.Now()

	for _, key := range keys {
		go func(k string) {
			throttle.Wait(k)
			done <- struct{}{}
		}(key)
	}

	for range keys {
		select {
		case <-done:
		case <-time.After(100 * time.Millisecond):
			t.Fatal("different-key requests should finish almost immediately")
		}
	}

	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Fatalf("expected different-key requests to finish quickly, got %v", elapsed)
	}
}
