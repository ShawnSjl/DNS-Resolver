package request_throttle

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestThrottleEntryInterval_Default(t *testing.T) {
	ctx := context.Background()
	entry := newThrottleEntry(ctx, 0*time.Millisecond)
	if entry.interval != defaultInterval {
		t.Fatal("expected default interval")
	}
}

func TestThrottleEntryInterval_Minimum(t *testing.T) {
	ctx := context.Background()
	entry := newThrottleEntry(ctx, 1*time.Millisecond)
	if entry.interval != minimumInterval {
		t.Fatal("expected minimum interval")
	}
}

func TestThrottleEntryInterval_Custom(t *testing.T) {
	ctx := context.Background()
	entry := newThrottleEntry(ctx, 400*time.Millisecond)
	if entry.interval != 400*time.Millisecond {
		t.Fatal("expected exact interval")
	}
}

func TestThrottleEntryWait(t *testing.T) {
	const interval = 200 * time.Millisecond
	const tolerance = 10 * time.Millisecond

	ctx := context.Background()
	entry := newThrottleEntry(ctx, interval)

	var wg sync.WaitGroup
	wg.Add(2)

	times := make([]time.Time, 2)

	start := time.Now()

	for i := 0; i < 2; i++ {
		go func(idx int) {
			defer wg.Done()

			entry.wait()
			times[idx] = time.Now()
		}(i)
	}

	wg.Wait()

	// order the times
	if times[0].After(times[1]) {
		times[0], times[1] = times[1], times[0]
	}

	diff := times[1].Sub(times[0])

	if diff < interval-tolerance {
		t.Fatalf("expected at least 200ms between releases, got %v", diff)
	}

	t.Logf("first release:  %v", times[0].Sub(start))
	t.Logf("second release: %v", times[1].Sub(start))
	t.Logf("interval:       %v", diff)
}

func TestThrottleEntryWait_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entry := newThrottleEntry(ctx, 5*time.Second)

	done := make(chan struct{})

	go func() {
		entry.wait()
		close(done)
	}()

	time.Sleep(50 * time.Millisecond) // ensure wait() has started

	start := time.Now()
	cancel()

	select {
	case <-done:
		if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
			t.Fatalf("wait() returned too slowly after context cancellation: %v", elapsed)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("wait() did not return after context cancellation")
	}
}
