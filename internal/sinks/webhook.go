package sinks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/firatmio/mcp-audit-proxy/internal/config"
	"github.com/firatmio/mcp-audit-proxy/internal/interceptor"
)

// requestTimeout bounds a single delivery attempt.
const requestTimeout = 10 * time.Second

// maxErrorBody is how much of a failed response we quote back to the user.
const maxErrorBody = 200

// Webhook posts audit events to an HTTP endpoint. It is an optional sink: the
// Dispatcher gives it its own goroutine and drops events rather than let it
// slow down the proxy.
type Webhook struct {
	url     string
	format  string
	send    string
	client  *http.Client
	backoff Backoff
}

// NewWebhook builds a webhook sink from configuration.
func NewWebhook(cfg config.WebhookSink) (*Webhook, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("webhook sink needs a URL")
	}
	return &Webhook{
		url:     cfg.URL,
		format:  cfg.ResolvedFormat(),
		send:    cfg.ResolvedSend(),
		client:  &http.Client{Timeout: requestTimeout},
		backoff: DefaultBackoff,
	}, nil
}

// Name implements Sink.
func (w *Webhook) Name() string { return "webhook" }

// Format returns the resolved payload format, for CLI output.
func (w *Webhook) Format() string { return w.format }

// Send returns which events this sink ships, for CLI output.
func (w *Webhook) Send() string { return w.send }

// Write delivers one event, retrying briefly on a failure that might be
// temporary.
func (w *Webhook) Write(ctx context.Context, event interceptor.ToolCallEvent) error {
	if !w.shouldSend(event) {
		return nil
	}

	payload, err := w.render(event)
	if err != nil {
		return err
	}

	return w.backoff.Do(ctx, func(int) error {
		return w.post(ctx, payload)
	})
}

// shouldSend applies the `send` selector.
func (w *Webhook) shouldSend(event interceptor.ToolCallEvent) bool {
	if w.send == config.SendFlagged {
		return len(event.PolicyFlags) > 0
	}
	return true
}

// render turns an event into the body for the configured format.
func (w *Webhook) render(event interceptor.ToolCallEvent) ([]byte, error) {
	var body any
	switch w.format {
	case config.FormatSlack:
		body = map[string]string{"text": summarise(event)}
	case config.FormatDiscord:
		body = map[string]string{"content": summarise(event)}
	default:
		// Generic: the audit record itself, so a SIEM gets the whole thing.
		body = event
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("cannot serialise event %s for the webhook: %w", event.EventID, err)
	}
	return encoded, nil
}

// post performs one delivery attempt.
func (w *Webhook) post(ctx context.Context, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(payload))
	if err != nil {
		// A URL that will not build a request will never build one.
		return Permanent(fmt.Errorf("cannot build the webhook request: %w", err))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "mcp-audit")

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the webhook at %s: %w", w.url, err)
	}
	defer resp.Body.Close()

	// Drain a little of the body so the connection can be reused, and keep it
	// for the error message.
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	io.Copy(io.Discard, resp.Body)

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusRequestTimeout,
		resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode >= 500:
		return fmt.Errorf("webhook at %s returned %s: %s", w.url, resp.Status, trim(snippet))
	default:
		// 4xx other than the two above: the request itself is wrong, and
		// sending it again will not change that.
		return Permanent(fmt.Errorf("webhook at %s rejected the event with %s: %s",
			w.url, resp.Status, trim(snippet)))
	}
}

// trim renders a response snippet on one line.
func trim(body []byte) string {
	text := strings.Join(strings.Fields(string(body)), " ")
	if text == "" {
		return "(empty response)"
	}
	return text
}

// summarise renders an event as one human-readable line, for a chat channel.
func summarise(event interceptor.ToolCallEvent) string {
	var b strings.Builder

	if len(event.PolicyFlags) > 0 {
		b.WriteString("[ALERT ")
		b.WriteString(strings.Join(event.PolicyFlags, ", "))
		b.WriteString("] ")
	}

	b.WriteString("mcp-audit: ")
	if event.ToolName != "" {
		fmt.Fprintf(&b, "%s %q", event.Direction, event.ToolName)
	} else {
		fmt.Fprintf(&b, "%s %s", event.Direction, event.Method)
	}
	fmt.Fprintf(&b, " on server %q", event.ServerName)
	if event.ClientID != "" {
		fmt.Fprintf(&b, " (client %s)", event.ClientID)
	}

	if len(event.Arguments) > 0 {
		fmt.Fprintf(&b, "\narguments: %s", truncate(string(event.Arguments), 300))
	}
	if event.Error != "" {
		fmt.Fprintf(&b, "\nerror: %s", event.Error)
	}
	fmt.Fprintf(&b, "\nat %s (event %s)", event.Timestamp.Format(time.RFC3339), event.EventID)

	return b.String()
}

// truncate shortens s to at most limit characters.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}
