package sinks

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fastBackoff keeps the retry tests quick while still exercising the schedule.
var fastBackoff = Backoff{Attempts: 4, Initial: time.Millisecond, Max: 5 * time.Millisecond, Jitter: 0.2}

func TestRetrySucceedsOnFirstAttempt(t *testing.T) {
	calls := 0
	err := fastBackoff.Do(context.Background(), func(int) error {
		calls++
		return nil
	})

	if err != nil {
		t.Fatalf("Do error = %v, want nil", err)
	}
	if calls != 1 {
		t.Errorf("op called %d times, want 1", calls)
	}
}

func TestRetryRecoversFromATemporaryFailure(t *testing.T) {
	calls := 0
	err := fastBackoff.Do(context.Background(), func(attempt int) error {
		calls++
		if attempt < 3 {
			return errors.New("connection refused")
		}
		return nil
	})

	if err != nil {
		t.Fatalf("Do error = %v, want the third attempt to succeed", err)
	}
	if calls != 3 {
		t.Errorf("op called %d times, want 3", calls)
	}
}

func TestRetryGivesUpAfterTheAttemptBudget(t *testing.T) {
	calls := 0
	err := fastBackoff.Do(context.Background(), func(int) error {
		calls++
		return errors.New("still down")
	})

	if err == nil {
		t.Fatal("Do error = nil, want a failure after the attempts run out")
	}
	if calls != fastBackoff.Attempts {
		t.Errorf("op called %d times, want %d", calls, fastBackoff.Attempts)
	}
	if !strings.Contains(err.Error(), "still down") {
		t.Errorf("error = %q, want it to carry the last real failure", err)
	}
	if !strings.Contains(err.Error(), "4 attempts") {
		t.Errorf("error = %q, want it to say how many attempts were made", err)
	}
}

func TestRetryStopsOnAPermanentError(t *testing.T) {
	calls := 0
	err := fastBackoff.Do(context.Background(), func(int) error {
		calls++
		return Permanent(errors.New("401 unauthorized"))
	})

	if err == nil {
		t.Fatal("Do error = nil, want the permanent failure returned")
	}
	if calls != 1 {
		t.Errorf("op called %d times; a permanent error must not be retried", calls)
	}
	if !IsPermanent(err) {
		t.Error("IsPermanent(err) = false, want the marker preserved")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error = %q, want the original message", err)
	}
}

func TestPermanentIsNilSafe(t *testing.T) {
	if err := Permanent(nil); err != nil {
		t.Errorf("Permanent(nil) = %v, want nil", err)
	}
	if IsPermanent(errors.New("ordinary")) {
		t.Error("IsPermanent(ordinary error) = true, want false")
	}
}

func TestRetryStopsWhenTheContextIsCancelled(t *testing.T) {
	// Shutdown must not wait for the whole retry budget of a dead endpoint.
	slow := Backoff{Attempts: 10, Initial: 200 * time.Millisecond, Max: time.Second}
	ctx, cancel := context.WithCancel(context.Background())

	calls := 0
	done := make(chan error, 1)
	go func() {
		done <- slow.Do(ctx, func(int) error {
			calls++
			return errors.New("unreachable")
		})
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Do error = nil, want the cancellation reported")
		}
		if !strings.Contains(err.Error(), "unreachable") {
			t.Errorf("error = %q, want it to keep the real failure", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Do ignored its cancelled context")
	}

	if calls > 2 {
		t.Errorf("op called %d times after an immediate cancel, want at most 2", calls)
	}
}

func TestRetryRespectsAnAlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	calls := 0
	err := fastBackoff.Do(ctx, func(int) error {
		calls++
		return nil
	})

	if err == nil {
		t.Fatal("Do error = nil for an already-cancelled context, want an error")
	}
	if calls != 0 {
		t.Errorf("op called %d times, want 0", calls)
	}
}

func TestBackoffDelaysGrowAndAreCapped(t *testing.T) {
	// Attempts are separated by growing waits: with Initial 20ms and four
	// attempts the total is at least 20+40+80 = 140ms, minus jitter.
	b := Backoff{Attempts: 4, Initial: 20 * time.Millisecond, Max: 100 * time.Millisecond, Jitter: 0}

	start := time.Now()
	_ = b.Do(context.Background(), func(int) error { return errors.New("down") })
	elapsed := time.Since(start)

	if elapsed < 130*time.Millisecond {
		t.Errorf("elapsed = %s, want the delays to grow exponentially", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Errorf("elapsed = %s, want the schedule to stay bounded", elapsed)
	}
}

func TestBackoffTreatsZeroAttemptsAsOne(t *testing.T) {
	calls := 0
	_ = Backoff{}.Do(context.Background(), func(int) error {
		calls++
		return errors.New("nope")
	})

	if calls != 1 {
		t.Errorf("op called %d times, want exactly 1", calls)
	}
}

func TestJitterStaysWithinBounds(t *testing.T) {
	for i := 0; i < 200; i++ {
		got := jitter(100*time.Millisecond, 0.2)
		if got < 80*time.Millisecond || got > 120*time.Millisecond {
			t.Fatalf("jitter(100ms, 0.2) = %s, want it within 80-120ms", got)
		}
	}
	if got := jitter(100*time.Millisecond, 0); got != 100*time.Millisecond {
		t.Errorf("jitter with no fraction = %s, want it unchanged", got)
	}
}
