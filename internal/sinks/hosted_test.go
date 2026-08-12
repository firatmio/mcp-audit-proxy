package sinks

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/firatmio/mcp-audit-proxy/internal/config"
	"github.com/firatmio/mcp-audit-proxy/internal/interceptor"
)

// ingestRecorder is a stand-in for the hosted backend. It decompresses and
// decodes what it receives, so the tests assert on events rather than bytes.
type ingestRecorder struct {
	mu       sync.Mutex
	requests []*http.Request
	batches  [][]interceptor.ToolCallEvent
	status   int
	// failuresLeft counts how many requests fail before one succeeds.
	failuresLeft int
	decodeErr    error
}

func (r *ingestRecorder) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		body, events, err := decodeIngest(req)
		_ = body

		r.mu.Lock()
		r.requests = append(r.requests, req.Clone(context.Background()))
		if err != nil {
			r.decodeErr = err
		} else {
			r.batches = append(r.batches, events)
		}
		status := r.status
		if r.failuresLeft > 0 {
			r.failuresLeft--
			status = http.StatusServiceUnavailable
		}
		r.mu.Unlock()

		if status == 0 {
			status = http.StatusAccepted
		}
		w.WriteHeader(status)
	}
}

func decodeIngest(req *http.Request) ([]byte, []interceptor.ToolCallEvent, error) {
	var reader io.Reader = req.Body
	if req.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(req.Body)
		if err != nil {
			return nil, nil, err
		}
		defer gz.Close()
		reader = gz
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, err
	}
	var parsed ingestRequest
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return raw, nil, err
	}
	return raw, parsed.Events, nil
}

func (r *ingestRecorder) snapshot() ([][]interceptor.ToolCallEvent, []*http.Request, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]interceptor.ToolCallEvent(nil), r.batches...),
		append([]*http.Request(nil), r.requests...),
		r.decodeErr
}

// newHostedTo builds a hosted sink pointed at url with small, fast batching.
func newHostedTo(t *testing.T, url string, batchSize int, flushInterval time.Duration) *Hosted {
	t.Helper()
	h, err := newHosted(config.HostedSink{Endpoint: url, APIKey: "test-key-abc123"})
	if err != nil {
		t.Fatalf("newHosted error = %v", err)
	}
	h.batchSize = batchSize
	h.flushInterval = flushInterval
	h.backoff = fastBackoff
	h.start()
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func TestHostedBatchesUntilFull(t *testing.T) {
	rec := &ingestRecorder{}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	h := newHostedTo(t, server.URL, 3, time.Hour) // ticker effectively off

	for i := 0; i < 2; i++ {
		if err := h.Write(context.Background(), testEvent("read_file")); err != nil {
			t.Fatalf("Write error = %v", err)
		}
	}
	if batches, _, _ := rec.snapshot(); len(batches) != 0 {
		t.Fatalf("backend received %d batches before the batch was full, want 0", len(batches))
	}
	if h.Pending() != 2 {
		t.Errorf("Pending() = %d, want 2", h.Pending())
	}

	// The third event fills the batch and ships it.
	if err := h.Write(context.Background(), testEvent("list_users")); err != nil {
		t.Fatalf("Write error = %v", err)
	}

	batches, _, decodeErr := rec.snapshot()
	if decodeErr != nil {
		t.Fatalf("backend could not decode the request: %v", decodeErr)
	}
	if len(batches) != 1 {
		t.Fatalf("backend received %d batches, want 1", len(batches))
	}
	if len(batches[0]) != 3 {
		t.Errorf("batch held %d events, want 3", len(batches[0]))
	}
	if batches[0][2].ToolName != "list_users" {
		t.Errorf("last event tool = %q, want list_users", batches[0][2].ToolName)
	}
	if h.Pending() != 0 {
		t.Errorf("Pending() = %d after a flush, want 0", h.Pending())
	}
}

func TestHostedRequestShape(t *testing.T) {
	rec := &ingestRecorder{}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	h := newHostedTo(t, server.URL, 1, time.Hour)
	if err := h.Write(context.Background(), testEvent("read_file")); err != nil {
		t.Fatalf("Write error = %v", err)
	}

	_, requests, _ := rec.snapshot()
	if len(requests) != 1 {
		t.Fatalf("backend received %d requests, want 1", len(requests))
	}
	req := requests[0]

	if got := req.Header.Get("Authorization"); got != "Bearer test-key-abc123" {
		t.Errorf("Authorization = %q, want a bearer token", got)
	}
	if got := req.Header.Get("Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", got)
	}
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if req.Method != http.MethodPost {
		t.Errorf("method = %s, want POST", req.Method)
	}
}

func TestHostedEventsKeepTheirIdentity(t *testing.T) {
	// Ingest is idempotent on event_id, so a retried batch must carry the same
	// ids it carried the first time.
	rec := &ingestRecorder{failuresLeft: 2}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	h := newHostedTo(t, server.URL, 1, time.Hour)
	event := testEvent("read_file")
	if err := h.Write(context.Background(), event); err != nil {
		t.Fatalf("Write error = %v", err)
	}

	batches, _, _ := rec.snapshot()
	if len(batches) != 3 {
		t.Fatalf("backend saw %d attempts, want 3 (two failures then a success)", len(batches))
	}
	for i, batch := range batches {
		if len(batch) != 1 || batch[0].EventID != event.EventID {
			t.Errorf("attempt %d carried %+v, want the same event id %s", i+1, batch, event.EventID)
		}
	}
}

func TestHostedTickerFlushesAPartialBatch(t *testing.T) {
	rec := &ingestRecorder{}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	// A batch size that will never be reached, so only the ticker can deliver.
	h := newHostedTo(t, server.URL, 1000, 20*time.Millisecond)
	if err := h.Write(context.Background(), testEvent("read_file")); err != nil {
		t.Fatalf("Write error = %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if batches, _, _ := rec.snapshot(); len(batches) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the ticker never flushed a partial batch; a quiet session would never deliver")
}

func TestHostedCloseFlushesWhatIsLeft(t *testing.T) {
	rec := &ingestRecorder{}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	h, err := newHosted(config.HostedSink{Endpoint: server.URL, APIKey: "k"})
	if err != nil {
		t.Fatalf("newHosted error = %v", err)
	}
	h.batchSize = 1000
	h.flushInterval = time.Hour
	h.backoff = fastBackoff
	h.start()

	for i := 0; i < 4; i++ {
		if err := h.Write(context.Background(), testEvent("read_file")); err != nil {
			t.Fatalf("Write error = %v", err)
		}
	}
	if batches, _, _ := rec.snapshot(); len(batches) != 0 {
		t.Fatalf("something shipped before Close, want nothing")
	}

	if err := h.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}

	batches, _, _ := rec.snapshot()
	if len(batches) != 1 || len(batches[0]) != 4 {
		t.Fatalf("Close delivered %+v, want one batch of 4 events", batches)
	}
	if err := h.Close(); err != nil {
		t.Errorf("second Close error = %v, want nil", err)
	}
}

func TestHostedRetriesServerErrors(t *testing.T) {
	rec := &ingestRecorder{status: http.StatusInternalServerError}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	h := newHostedTo(t, server.URL, 1, time.Hour)
	err := h.Write(context.Background(), testEvent("read_file"))

	if err == nil {
		t.Fatal("Write error = nil, want a failure after the retries run out")
	}
	if batches, _, _ := rec.snapshot(); len(batches) != fastBackoff.Attempts {
		t.Errorf("backend saw %d attempts, want %d", len(batches), fastBackoff.Attempts)
	}
}

func TestHostedDoesNotRetryABadAPIKey(t *testing.T) {
	// Hammering an auth endpoint with a key that will never work just earns a
	// rate limit on top of the original problem.
	rec := &ingestRecorder{status: http.StatusUnauthorized}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	h := newHostedTo(t, server.URL, 1, time.Hour)
	err := h.Write(context.Background(), testEvent("read_file"))

	if err == nil {
		t.Fatal("Write error = nil, want the rejection reported")
	}
	if batches, _, _ := rec.snapshot(); len(batches) != 1 {
		t.Errorf("backend saw %d attempts, want exactly 1", len(batches))
	}
	if !strings.Contains(err.Error(), "api_key") {
		t.Errorf("error = %q, want it to point at the api_key setting", err)
	}
}

func TestHostedNeverLeaksTheAPIKeyIntoErrors(t *testing.T) {
	const secret = "super-secret-key-do-not-log"

	// Every failure path: unreachable, rejected, and server error.
	rejecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer rejecting.Close()
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	for _, url := range []string{rejecting.URL, deadURL} {
		h, err := newHosted(config.HostedSink{Endpoint: url, APIKey: secret})
		if err != nil {
			t.Fatalf("newHosted error = %v", err)
		}
		h.batchSize = 1
		h.backoff = fastBackoff

		writeErr := h.Write(context.Background(), testEvent("read_file"))
		if writeErr == nil {
			t.Fatalf("Write to %s error = nil, want a failure", url)
		}
		if strings.Contains(writeErr.Error(), secret) {
			t.Errorf("error message leaks the api key: %q", writeErr)
		}
	}
}

func TestHostedRejectsPlainHTTP(t *testing.T) {
	// Audit events carry tool arguments; shipping them unencrypted would undo
	// the point of the tool.
	_, err := newHosted(config.HostedSink{Endpoint: "http://api.example.com/v1/events", APIKey: "k"})
	if err == nil {
		t.Fatal("newHosted accepted a plain http endpoint, want an error")
	}
	if !strings.Contains(err.Error(), "https://") {
		t.Errorf("error = %q, want it to say https is required", err)
	}
}

func TestHostedAllowsHTTPSAndLoopback(t *testing.T) {
	ok := []string{
		"https://api.mcp-audit.dev/v1/events",
		"http://127.0.0.1:8080/v1/events",
		"http://localhost:8080/v1/events",
		"http://[::1]:8080/v1/events",
	}
	for _, endpoint := range ok {
		if _, err := newHosted(config.HostedSink{Endpoint: endpoint, APIKey: "k"}); err != nil {
			t.Errorf("newHosted(%q) error = %v, want it accepted", endpoint, err)
		}
	}
}

func TestHostedRequiresEndpointAndKey(t *testing.T) {
	if _, err := newHosted(config.HostedSink{APIKey: "k"}); err == nil {
		t.Error("newHosted without an endpoint error = nil, want an error")
	}
	if _, err := newHosted(config.HostedSink{Endpoint: "https://x/y"}); err == nil {
		t.Error("newHosted without an api key error = nil, want an error")
	}
}

func TestHostedFailureDoesNotAffectTheLocalLog(t *testing.T) {
	// The guarantee that matters, again: the paid backend being down must not
	// cost an audit record on disk.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	path := t.TempDir() + "/events.jsonl"
	jsonl, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL error = %v", err)
	}

	h, err := newHosted(config.HostedSink{Endpoint: server.URL, APIKey: "k"})
	if err != nil {
		t.Fatalf("newHosted error = %v", err)
	}
	h.batchSize = 1
	h.backoff = fastBackoff
	h.start()

	d := NewDispatcher(nil)
	d.Add(jsonl, true)
	d.Add(h, false)

	for i := 0; i < 5; i++ {
		d.Dispatch(testEvent("read_file"))
	}
	d.Close()

	if lines := readLines(t, path); len(lines) != 5 {
		t.Errorf("local log has %d lines, want 5 despite the backend being down", len(lines))
	}
}

func TestHostedIsClosedByTheDispatcher(t *testing.T) {
	// Dispatcher.Close must reach the sink's Close, which is what ships the
	// final partial batch.
	rec := &ingestRecorder{}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	h, err := newHosted(config.HostedSink{Endpoint: server.URL, APIKey: "k"})
	if err != nil {
		t.Fatalf("newHosted error = %v", err)
	}
	h.batchSize = 1000 // never reached
	h.flushInterval = time.Hour
	h.backoff = fastBackoff
	h.start()

	d := NewDispatcher(nil)
	d.Add(h, false)
	d.Dispatch(testEvent("read_file"))
	d.Dispatch(testEvent("list_users"))
	d.Close()

	batches, _, _ := rec.snapshot()
	if len(batches) != 1 || len(batches[0]) != 2 {
		t.Errorf("backend received %+v, want one final batch of 2 events", batches)
	}
}

func TestHostedRejectsAnOversizedBatch(t *testing.T) {
	rec := &ingestRecorder{}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	h := newHostedTo(t, server.URL, 2, time.Hour)

	// Two events whose results alone exceed the cap.
	huge := testEvent("read_file")
	huge.Result = json.RawMessage(`"` + strings.Repeat("x", maxBatchBytes/2+1024) + `"`)

	_ = h.Write(context.Background(), huge)
	err := h.Write(context.Background(), huge)

	if err == nil {
		t.Fatal("Write error = nil for an oversized batch, want an error")
	}
	if !strings.Contains(err.Error(), "not sent") {
		t.Errorf("error = %q, want it to say the batch was not sent", err)
	}
	if batches, _, _ := rec.snapshot(); len(batches) != 0 {
		t.Errorf("an oversized batch reached the backend: %d requests", len(batches))
	}
}

func TestHostedFlushOnAnEmptyBatchIsANoOp(t *testing.T) {
	rec := &ingestRecorder{}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	h := newHostedTo(t, server.URL, 10, time.Hour)
	if err := h.Flush(context.Background()); err != nil {
		t.Fatalf("Flush on an empty batch error = %v, want nil", err)
	}
	if batches, _, _ := rec.snapshot(); len(batches) != 0 {
		t.Errorf("an empty flush sent %d requests, want 0", len(batches))
	}
}

func TestHostedGzipActuallyCompresses(t *testing.T) {
	// Audit batches are JSON with heavily repeated structure; if this ever
	// stops paying off, the header is a lie worth removing.
	events := make([]interceptor.ToolCallEvent, 50)
	for i := range events {
		events[i] = testEvent("read_file")
	}
	raw, err := json.Marshal(ingestRequest{Events: events})
	if err != nil {
		t.Fatalf("marshal error = %v", err)
	}

	compressed, err := gzipBytes(raw)
	if err != nil {
		t.Fatalf("gzipBytes error = %v", err)
	}
	if len(compressed) >= len(raw) {
		t.Errorf("gzip produced %d bytes from %d; compression is not paying off", len(compressed), len(raw))
	}
	t.Logf("batch of %d events: %d bytes raw, %d gzipped (%.0f%%)",
		len(events), len(raw), len(compressed), 100*float64(len(compressed))/float64(len(raw)))
}
