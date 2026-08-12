package sinks

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/firatmio/mcp-audit-proxy/internal/config"
	"github.com/firatmio/mcp-audit-proxy/internal/interceptor"
)

// The hosted sink ships audit events to the Team-tier backend.
//
// It differs from the webhook sink in one way that matters: it batches. A
// webhook is an alerting channel and one message per event is the point; this
// is a log shipper, and a request per event would be wasteful for both sides.
//
// Everything else follows the rules every optional sink follows — it is
// best-effort, it never blocks the proxy, and its failure never costs the local
// JSONL log an event.

// Batching defaults. Chosen so a busy session ships promptly without one
// request per tool call, and an idle one still delivers within a few seconds.
const (
	defaultBatchSize     = 50
	defaultFlushInterval = 5 * time.Second
)

// maxBatchBytes caps the uncompressed size of one request. Tool results can be
// large, and a batch of them should not turn into a request the backend
// rejects outright.
const maxBatchBytes = 4 << 20 // 4 MiB

// Hosted delivers batches of audit events to the hosted backend.
type Hosted struct {
	endpoint string
	apiKey   string
	client   *http.Client
	backoff  Backoff

	batchSize     int
	flushInterval time.Duration

	mu    sync.Mutex
	batch []interceptor.ToolCallEvent

	// ticker flushes partial batches so a quiet session still delivers.
	stopTicker chan struct{}
	tickerDone chan struct{}
	closeOnce  sync.Once
}

// NewHosted builds a hosted sink from configuration and starts its flush
// ticker.
func NewHosted(cfg config.HostedSink) (*Hosted, error) {
	h, err := newHosted(cfg)
	if err != nil {
		return nil, err
	}
	h.start()
	return h, nil
}

// newHosted builds the sink without starting the ticker, so that tests can
// shorten the batching parameters before it runs.
func newHosted(cfg config.HostedSink) (*Hosted, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("hosted sink needs an endpoint")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("hosted sink needs an api_key")
	}
	if err := checkEndpointIsSafe(cfg.Endpoint); err != nil {
		return nil, err
	}

	return &Hosted{
		endpoint:      cfg.Endpoint,
		apiKey:        cfg.APIKey,
		client:        &http.Client{Timeout: requestTimeout},
		backoff:       DefaultBackoff,
		batchSize:     defaultBatchSize,
		flushInterval: defaultFlushInterval,
		stopTicker:    make(chan struct{}),
		tickerDone:    make(chan struct{}),
	}, nil
}

// start launches the background flusher.
func (h *Hosted) start() { go h.runTicker() }

// checkEndpointIsSafe refuses to ship audit data over plain HTTP.
//
// Audit events carry tool arguments, which routinely hold secrets. Sending
// them unencrypted would undo the point of the tool. Loopback is allowed so
// the backend can be developed against.
func checkEndpointIsSafe(endpoint string) error {
	lower := strings.ToLower(endpoint)
	if strings.HasPrefix(lower, "https://") {
		return nil
	}
	if strings.HasPrefix(lower, "http://127.0.0.1") ||
		strings.HasPrefix(lower, "http://localhost") ||
		strings.HasPrefix(lower, "http://[::1]") {
		return nil
	}
	return fmt.Errorf("sinks.hosted.endpoint must use https:// (got %q); audit events carry tool arguments, which routinely hold secrets", endpoint)
}

// Name implements Sink.
func (h *Hosted) Name() string { return "hosted" }

// Endpoint returns the configured endpoint, for CLI output. The API key is
// never returned or logged anywhere.
func (h *Hosted) Endpoint() string { return h.endpoint }

// Write adds an event to the current batch, shipping it once the batch is
// full.
//
// The Dispatcher calls this from the sink's own goroutine, so flushing inline
// is deliberate: it applies backpressure through that one queue and nowhere
// else.
func (h *Hosted) Write(ctx context.Context, event interceptor.ToolCallEvent) error {
	h.mu.Lock()
	h.batch = append(h.batch, event)
	full := len(h.batch) >= h.batchSize
	h.mu.Unlock()

	if !full {
		return nil
	}
	return h.Flush(ctx)
}

// runTicker flushes partial batches on an interval.
func (h *Hosted) runTicker() {
	defer close(h.tickerDone)

	ticker := time.NewTicker(h.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// A failure here has already been retried; there is nobody to
			// return it to, so drop it and keep the proxy moving.
			_ = h.Flush(context.Background())
		case <-h.stopTicker:
			return
		}
	}
}

// Flush ships whatever is batched. It is safe to call when nothing is pending.
func (h *Hosted) Flush(ctx context.Context) error {
	h.mu.Lock()
	if len(h.batch) == 0 {
		h.mu.Unlock()
		return nil
	}
	batch := h.batch
	h.batch = nil
	h.mu.Unlock()

	return h.send(ctx, batch)
}

// ingestRequest is the wire format the backend receives.
type ingestRequest struct {
	// Events carry their own EventID, which is what makes ingest idempotent:
	// a retried batch must not produce duplicates.
	Events []interceptor.ToolCallEvent `json:"events"`
}

// send delivers one batch, retrying briefly on a failure that might be
// temporary.
func (h *Hosted) send(ctx context.Context, batch []interceptor.ToolCallEvent) error {
	body, err := json.Marshal(ingestRequest{Events: batch})
	if err != nil {
		return fmt.Errorf("cannot serialise a batch of %d event(s): %w", len(batch), err)
	}
	if len(body) > maxBatchBytes {
		return fmt.Errorf("a batch of %d event(s) is %d bytes, over the %d byte limit; it was not sent",
			len(batch), len(body), maxBatchBytes)
	}

	compressed, err := gzipBytes(body)
	if err != nil {
		return err
	}

	return h.backoff.Do(ctx, func(int) error {
		return h.post(ctx, compressed, len(batch))
	})
}

// gzipBytes compresses a request body. Audit batches are JSON with a lot of
// repeated structure, so this is a large saving for a small cost.
func gzipBytes(body []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(body); err != nil {
		writer.Close()
		return nil, fmt.Errorf("cannot compress the batch: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("cannot compress the batch: %w", err)
	}
	return buf.Bytes(), nil
}

// post performs one delivery attempt.
func (h *Hosted) post(ctx context.Context, body []byte, eventCount int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint, bytes.NewReader(body))
	if err != nil {
		return Permanent(fmt.Errorf("cannot build the ingest request: %w", err))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Authorization", "Bearer "+h.apiKey)
	req.Header.Set("User-Agent", "mcp-audit")

	resp, err := h.client.Do(req)
	if err != nil {
		// The URL is in the config, but the API key must never reach a log
		// line, so the error is built from our own fields rather than from
		// whatever the transport chose to include.
		return fmt.Errorf("cannot reach the hosted backend at %s: %w", h.endpoint, err)
	}
	defer resp.Body.Close()

	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	io.Copy(io.Discard, resp.Body)

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		// A bad key will be just as bad next time, and hammering an auth
		// endpoint is how you get rate limited on top of it.
		return Permanent(fmt.Errorf("the hosted backend rejected the api_key (%s); check sinks.hosted.api_key", resp.Status))
	case resp.StatusCode == http.StatusRequestEntityTooLarge:
		return Permanent(fmt.Errorf("the hosted backend rejected a batch of %d event(s) as too large (%s)", eventCount, resp.Status))
	case resp.StatusCode == http.StatusRequestTimeout,
		resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode >= 500:
		return fmt.Errorf("the hosted backend returned %s: %s", resp.Status, trim(snippet))
	default:
		return Permanent(fmt.Errorf("the hosted backend rejected %d event(s) with %s: %s",
			eventCount, resp.Status, trim(snippet)))
	}
}

// Close stops the flush ticker and ships whatever is left.
//
// The Dispatcher calls this after every worker has stopped, so no Write can be
// in flight and the final batch is genuinely final.
func (h *Hosted) Close() error {
	var err error
	h.closeOnce.Do(func() {
		close(h.stopTicker)
		<-h.tickerDone

		// A short budget of its own: shutdown should not hang on a backend
		// that has stopped answering.
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		defer cancel()
		err = h.Flush(ctx)
	})
	return err
}

// Pending reports how many events are batched but not yet sent. Used by tests
// and by the CLI's shutdown summary.
func (h *Hosted) Pending() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.batch)
}
