// Package sinks delivers audit events to their destinations.
//
// The contract that matters: the local JSONL log is required and must never
// lose an event, while every other sink is best-effort and must never slow the
// proxy down. The Dispatcher enforces exactly that distinction.
package sinks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/firatmio/mcp-audit-proxy/internal/interceptor"
)

// Sink is one destination for audit events.
type Sink interface {
	// Write delivers a single event. It may block; the Dispatcher calls it
	// from a dedicated goroutine, never from the proxy's hot path.
	Write(ctx context.Context, event interceptor.ToolCallEvent) error
	// Name identifies the sink in log messages.
	Name() string
}

// defaultQueueSize is how many events may be in flight per sink.
const defaultQueueSize = 1024

// defaultDrainGrace is how long Close waits for the queues to empty before
// cancelling the sinks' context. Without it, shutting down while a webhook
// endpoint is unreachable would stall for the retry budget of every queued
// event.
const defaultDrainGrace = 5 * time.Second

// registration is one sink plus the machinery that feeds it.
type registration struct {
	sink     Sink
	queue    chan interceptor.ToolCallEvent
	required bool
	dropped  atomic.Uint64
	failed   atomic.Uint64
}

// Dispatcher fans one event out to every registered sink. Each sink gets its
// own queue and worker goroutine, so a slow webhook cannot hold up the local
// log — or the proxied MCP traffic.
type Dispatcher struct {
	regs   []*registration
	logger *log.Logger
	wg     sync.WaitGroup

	// ctx bounds the sinks' own work. Close cancels it once the drain grace
	// period expires, so a wedged network sink cannot hold up shutdown.
	ctx    context.Context
	cancel context.CancelFunc

	// drainGrace is how long Close waits before cutting the sinks off. Tests
	// shorten it; nothing else changes it.
	drainGrace time.Duration

	// done is closed by Close to signal shutdown.
	//
	// The queues themselves are deliberately never closed. Closing them would
	// mean a Dispatch that had already passed a "are we shutting down?" check
	// could then send on a closed channel and panic — and Dispatch runs on the
	// proxy's hot path, concurrently with shutdown, so that window is real.
	// Signalling through a separate channel removes it entirely.
	done chan struct{}

	closeOnce sync.Once
}

// NewDispatcher creates a Dispatcher that reports sink failures to logger.
// A nil logger discards the messages.
func NewDispatcher(logger *log.Logger) *Dispatcher {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Dispatcher{
		logger:     logger,
		ctx:        ctx,
		cancel:     cancel,
		drainGrace: defaultDrainGrace,
		done:       make(chan struct{}),
	}
}

// Add registers a sink and starts its worker.
//
// A required sink (the local JSONL log) applies backpressure when its queue is
// full: Dispatch blocks rather than dropping an audit record. An optional sink
// drops events instead, and the count is reported at shutdown.
func (d *Dispatcher) Add(sink Sink, required bool) {
	reg := &registration{
		sink:     sink,
		queue:    make(chan interceptor.ToolCallEvent, defaultQueueSize),
		required: required,
	}
	d.regs = append(d.regs, reg)

	d.wg.Add(1)
	go d.run(reg)
}

// run drains one sink's queue until shutdown is signalled, then finishes
// whatever is still queued before stopping.
func (d *Dispatcher) run(reg *registration) {
	defer d.wg.Done()
	for {
		select {
		case event := <-reg.queue:
			d.deliver(reg, event)
		case <-d.done:
			// Shutting down: take what is left, then stop.
			for {
				select {
				case event := <-reg.queue:
					d.deliver(reg, event)
				default:
					return
				}
			}
		}
	}
}

// deliver writes one event and records a failure.
func (d *Dispatcher) deliver(reg *registration, event interceptor.ToolCallEvent) {
	if err := reg.sink.Write(d.ctx, event); err != nil {
		reg.failed.Add(1)
		d.logger.Printf("sink %s failed to write event %s: %v", reg.sink.Name(), event.EventID, err)
	}
}

// Dispatch hands an event to every sink. It returns as soon as the event is
// queued; delivery happens on the sinks' own goroutines.
func (d *Dispatcher) Dispatch(event interceptor.ToolCallEvent) {
	select {
	case <-d.done:
		return
	default:
	}

	for _, reg := range d.regs {
		if reg.required {
			// A required sink gets backpressure rather than a dropped audit
			// record — but never at the cost of blocking shutdown forever.
			select {
			case reg.queue <- event:
			case <-d.done:
				return
			}
			continue
		}
		select {
		case reg.queue <- event:
		default:
			reg.dropped.Add(1)
		}
	}
}

// DispatchAll queues a slice of events, which is what a JSON-RPC batch yields.
func (d *Dispatcher) DispatchAll(events []interceptor.ToolCallEvent) {
	for _, event := range events {
		d.Dispatch(event)
	}
}

// Close drains every queue, stops the workers and closes any sink that
// implements io.Closer. It is safe to call more than once.
func (d *Dispatcher) Close() error {
	var err error
	d.closeOnce.Do(func() {
		close(d.done)

		// Give the workers a bounded window to finish what is queued, then
		// cut them off so shutdown stays predictable.
		drained := make(chan struct{})
		go func() {
			d.wg.Wait()
			close(drained)
		}()
		select {
		case <-drained:
		case <-time.After(d.drainGrace):
			d.logger.Printf("sinks did not drain within %s, abandoning what is left", d.drainGrace)
			d.cancel()
			<-drained
		}
		d.cancel()

		var errs []error
		for _, reg := range d.regs {
			if dropped := reg.dropped.Load(); dropped > 0 {
				d.logger.Printf("sink %s dropped %d event(s) because its queue was full", reg.sink.Name(), dropped)
			}
			closer, ok := reg.sink.(io.Closer)
			if !ok {
				continue
			}
			if cerr := closer.Close(); cerr != nil {
				errs = append(errs, fmt.Errorf("closing sink %s: %w", reg.sink.Name(), cerr))
			}
		}
		err = errors.Join(errs...)
	})
	return err
}

// Stats reports per-sink delivery counters, for the CLI's shutdown summary.
func (d *Dispatcher) Stats() map[string]Stat {
	out := make(map[string]Stat, len(d.regs))
	for _, reg := range d.regs {
		out[reg.sink.Name()] = Stat{
			Dropped: reg.dropped.Load(),
			Failed:  reg.failed.Load(),
		}
	}
	return out
}

// Stat holds the delivery counters of a single sink.
type Stat struct {
	// Dropped counts events discarded because an optional sink fell behind.
	Dropped uint64
	// Failed counts events whose Write returned an error.
	Failed uint64
}
