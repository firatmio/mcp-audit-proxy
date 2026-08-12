package sinks

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"
)

// Retrying a network sink is worth doing, but only briefly. Each optional sink
// has one worker goroutine draining one bounded queue, so time spent sleeping
// between attempts is time the queue is not moving — and a queue that stops
// moving drops events. A short, bounded schedule recovers from a blip without
// turning a sustained outage into data loss elsewhere.

// DefaultBackoff is the schedule the network sinks use: four attempts spread
// over roughly three seconds.
var DefaultBackoff = Backoff{
	Attempts: 4,
	Initial:  200 * time.Millisecond,
	Max:      2 * time.Second,
	Jitter:   0.2,
}

// Backoff is a bounded exponential backoff schedule.
type Backoff struct {
	// Attempts is the total number of tries, including the first one. Values
	// below 1 are treated as 1.
	Attempts int
	// Initial is how long to wait after the first failure.
	Initial time.Duration
	// Max caps a single wait, however many failures have accumulated.
	Max time.Duration
	// Jitter randomises each wait by up to this fraction, so that a fleet of
	// proxies recovering from the same outage does not retry in lockstep.
	// 0.2 means "somewhere between 80% and 120% of the computed delay".
	Jitter float64
}

// permanentError marks a failure that retrying cannot fix.
type permanentError struct{ err error }

func (p *permanentError) Error() string { return p.err.Error() }
func (p *permanentError) Unwrap() error { return p.err }

// Permanent wraps err to tell Do not to retry it. A malformed request or a
// rejected credential will fail identically every time; retrying only delays
// the queue.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanentError{err: err}
}

// IsPermanent reports whether err was marked with Permanent.
func IsPermanent(err error) bool {
	var p *permanentError
	return errors.As(err, &p)
}

// Do runs op until it succeeds, until the attempts run out, or until ctx is
// cancelled. attempt counts from 1.
//
// The error returned is the last one op produced, so the caller reports why the
// delivery actually failed rather than a generic "gave up".
func (b Backoff) Do(ctx context.Context, op func(attempt int) error) error {
	attempts := b.Attempts
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	delay := b.Initial

	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return fmt.Errorf("%w (giving up: %v)", lastErr, err)
			}
			return err
		}

		lastErr = op(attempt)
		if lastErr == nil {
			return nil
		}
		if IsPermanent(lastErr) {
			return lastErr
		}
		if attempt == attempts {
			break
		}

		wait := jitter(delay, b.Jitter)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("%w (giving up: %v)", lastErr, ctx.Err())
		case <-timer.C:
		}

		delay *= 2
		if b.Max > 0 && delay > b.Max {
			delay = b.Max
		}
	}

	return fmt.Errorf("gave up after %d attempts: %w", attempts, lastErr)
}

// jitter randomises d by up to fraction in either direction.
func jitter(d time.Duration, fraction float64) time.Duration {
	if fraction <= 0 || d <= 0 {
		return d
	}
	// rand without a seed is fine here: this is scheduling noise, not a
	// security decision.
	spread := float64(d) * fraction
	offset := (rand.Float64()*2 - 1) * spread
	jittered := time.Duration(float64(d) + offset)
	if jittered < 0 {
		return 0
	}
	return jittered
}
