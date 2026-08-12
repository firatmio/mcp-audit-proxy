package sinks

import (
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

// recorder is a stand-in webhook endpoint.
type recorder struct {
	mu     sync.Mutex
	bodies []string
	status int
	// failuresLeft counts how many requests still fail before one succeeds.
	failuresLeft int
}

func (r *recorder) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)

		r.mu.Lock()
		r.bodies = append(r.bodies, string(body))
		status := r.status
		if r.failuresLeft > 0 {
			r.failuresLeft--
			status = http.StatusServiceUnavailable
		}
		r.mu.Unlock()

		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
	}
}

func (r *recorder) received() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.bodies...)
}

// newWebhookTo builds a webhook sink pointed at url, with a fast retry
// schedule so the tests stay quick.
func newWebhookTo(t *testing.T, cfg config.WebhookSink) *Webhook {
	t.Helper()
	w, err := NewWebhook(cfg)
	if err != nil {
		t.Fatalf("NewWebhook error = %v", err)
	}
	w.backoff = fastBackoff
	return w
}

func flaggedEvent() interceptor.ToolCallEvent {
	ev := testEvent("shell_exec")
	ev.ClientID = "agent-1"
	ev.PolicyFlags = []string{"rbac_denied"}
	return ev
}

func TestWebhookPostsTheEventAsJSON(t *testing.T) {
	rec := &recorder{}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	w := newWebhookTo(t, config.WebhookSink{URL: server.URL})
	if err := w.Write(context.Background(), testEvent("read_file")); err != nil {
		t.Fatalf("Write error = %v", err)
	}

	bodies := rec.received()
	if len(bodies) != 1 {
		t.Fatalf("endpoint received %d requests, want 1", len(bodies))
	}

	var decoded interceptor.ToolCallEvent
	if err := json.Unmarshal([]byte(bodies[0]), &decoded); err != nil {
		t.Fatalf("body is not a serialised audit event: %v (%s)", err, bodies[0])
	}
	if decoded.ToolName != "read_file" {
		t.Errorf("tool_name = %q, want read_file", decoded.ToolName)
	}
}

func TestWebhookRetriesAServerError(t *testing.T) {
	rec := &recorder{failuresLeft: 2}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	w := newWebhookTo(t, config.WebhookSink{URL: server.URL})
	if err := w.Write(context.Background(), testEvent("read_file")); err != nil {
		t.Fatalf("Write error = %v, want the retry to succeed", err)
	}

	if got := len(rec.received()); got != 3 {
		t.Errorf("endpoint received %d requests, want 3 (two failures then a success)", got)
	}
}

func TestWebhookGivesUpOnASustainedOutage(t *testing.T) {
	rec := &recorder{status: http.StatusInternalServerError}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	w := newWebhookTo(t, config.WebhookSink{URL: server.URL})
	err := w.Write(context.Background(), testEvent("read_file"))

	if err == nil {
		t.Fatal("Write error = nil, want a failure after the retries run out")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want it to report the status code", err)
	}
	if got := len(rec.received()); got != fastBackoff.Attempts {
		t.Errorf("endpoint received %d requests, want %d", got, fastBackoff.Attempts)
	}
}

func TestWebhookDoesNotRetryARejection(t *testing.T) {
	// A 400 will fail identically every time; retrying only stalls the queue.
	rec := &recorder{status: http.StatusBadRequest}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	w := newWebhookTo(t, config.WebhookSink{URL: server.URL})
	err := w.Write(context.Background(), testEvent("read_file"))

	if err == nil {
		t.Fatal("Write error = nil, want the rejection reported")
	}
	if got := len(rec.received()); got != 1 {
		t.Errorf("endpoint received %d requests, want exactly 1", got)
	}
}

func TestWebhookRetriesRateLimiting(t *testing.T) {
	rec := &recorder{status: http.StatusTooManyRequests}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	w := newWebhookTo(t, config.WebhookSink{URL: server.URL})
	_ = w.Write(context.Background(), testEvent("read_file"))

	if got := len(rec.received()); got != fastBackoff.Attempts {
		t.Errorf("endpoint received %d requests, want 429 to be retried %d times", got, fastBackoff.Attempts)
	}
}

func TestWebhookSlackFormat(t *testing.T) {
	rec := &recorder{}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	w := newWebhookTo(t, config.WebhookSink{URL: server.URL, Format: config.FormatSlack, Send: config.SendAll})
	if err := w.Write(context.Background(), flaggedEvent()); err != nil {
		t.Fatalf("Write error = %v", err)
	}

	var payload map[string]string
	if err := json.Unmarshal([]byte(rec.received()[0]), &payload); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	text, ok := payload["text"]
	if !ok {
		t.Fatalf("Slack payload = %v, want a \"text\" key", payload)
	}
	for _, want := range []string{"shell_exec", "rbac_denied", "ALERT"} {
		if !strings.Contains(text, want) {
			t.Errorf("Slack text %q does not mention %q", text, want)
		}
	}
}

func TestWebhookDiscordFormat(t *testing.T) {
	rec := &recorder{}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	w := newWebhookTo(t, config.WebhookSink{URL: server.URL, Format: config.FormatDiscord, Send: config.SendAll})
	if err := w.Write(context.Background(), flaggedEvent()); err != nil {
		t.Fatalf("Write error = %v", err)
	}

	var payload map[string]string
	if err := json.Unmarshal([]byte(rec.received()[0]), &payload); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if _, ok := payload["content"]; !ok {
		t.Errorf("Discord payload = %v, want a \"content\" key", payload)
	}
}

func TestWebhookFlaggedOnlyFiltersUnflaggedEvents(t *testing.T) {
	rec := &recorder{}
	server := httptest.NewServer(rec.handler())
	defer server.Close()

	w := newWebhookTo(t, config.WebhookSink{URL: server.URL, Send: config.SendFlagged})

	if err := w.Write(context.Background(), testEvent("read_file")); err != nil {
		t.Fatalf("Write error = %v", err)
	}
	if got := len(rec.received()); got != 0 {
		t.Fatalf("endpoint received %d requests for an unflagged event, want 0", got)
	}

	if err := w.Write(context.Background(), flaggedEvent()); err != nil {
		t.Fatalf("Write error = %v", err)
	}
	if got := len(rec.received()); got != 1 {
		t.Errorf("endpoint received %d requests for a flagged event, want 1", got)
	}
}

func TestWebhookFormatAndSendDefaults(t *testing.T) {
	cases := []struct {
		name       string
		cfg        config.WebhookSink
		wantFormat string
		wantSend   string
	}{
		{
			"slack url is detected and defaults to alerts only",
			config.WebhookSink{URL: "https://hooks.slack.com/services/T000/B000/xxx"},
			config.FormatSlack, config.SendFlagged,
		},
		{
			"discord url is detected",
			config.WebhookSink{URL: "https://discord.com/api/webhooks/123/abc"},
			config.FormatDiscord, config.SendFlagged,
		},
		{
			"anything else is a generic siem feed and gets everything",
			config.WebhookSink{URL: "https://siem.internal/ingest"},
			config.FormatGeneric, config.SendAll,
		},
		{
			"an explicit format wins over detection",
			config.WebhookSink{URL: "https://hooks.slack.com/services/x", Format: config.FormatGeneric},
			config.FormatGeneric, config.SendAll,
		},
		{
			"an explicit send wins over the default",
			config.WebhookSink{URL: "https://siem.internal/ingest", Send: config.SendFlagged},
			config.FormatGeneric, config.SendFlagged,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.ResolvedFormat(); got != tc.wantFormat {
				t.Errorf("ResolvedFormat() = %q, want %q", got, tc.wantFormat)
			}
			if got := tc.cfg.ResolvedSend(); got != tc.wantSend {
				t.Errorf("ResolvedSend() = %q, want %q", got, tc.wantSend)
			}
		})
	}
}

func TestWebhookNeedsAURL(t *testing.T) {
	if _, err := NewWebhook(config.WebhookSink{}); err == nil {
		t.Fatal("NewWebhook without a URL error = nil, want an error")
	}
}

func TestWebhookFailureDoesNotAffectTheLocalLog(t *testing.T) {
	// The guarantee that matters: a dead webhook must not cost us an audit
	// record on disk.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	path := t.TempDir() + "/events.jsonl"
	jsonl, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL error = %v", err)
	}

	d := NewDispatcher(nil)
	d.Add(jsonl, true)
	d.Add(newWebhookTo(t, config.WebhookSink{URL: server.URL}), false)

	for i := 0; i < 3; i++ {
		d.Dispatch(testEvent("read_file"))
	}
	d.Close()

	if lines := readLines(t, path); len(lines) != 3 {
		t.Errorf("local log has %d lines, want 3 despite the webhook being down", len(lines))
	}
}

func TestDispatcherCloseIsNotHeldUpByADeadWebhook(t *testing.T) {
	// An endpoint that accepts the connection and then never answers.
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	// Cleanups run last-registered-first, so the handlers are released before
	// server.Close() waits for them.
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })

	w := newWebhookTo(t, config.WebhookSink{URL: server.URL})
	w.backoff = Backoff{Attempts: 10, Initial: time.Second, Max: 5 * time.Second}

	d := NewDispatcher(nil)
	d.drainGrace = 100 * time.Millisecond
	d.Add(w, false)
	for i := 0; i < 20; i++ {
		d.Dispatch(testEvent("read_file"))
	}

	start := time.Now()
	done := make(chan struct{})
	go func() {
		d.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close() hung on an unresponsive webhook")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Close() took %s; it must cut off a wedged sink promptly", elapsed)
	}
}
