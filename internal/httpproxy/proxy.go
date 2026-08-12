// Package httpproxy audits remote (Streamable HTTP) MCP servers by sitting in
// front of them as a reverse proxy.
//
// It shares the whole audit pipeline with the stdio wrapper — same interceptor,
// same policy engine, same sinks — and differs only in how it gets hold of the
// JSON-RPC bytes. Authentication is not touched: OAuth headers, session ids and
// cookies are forwarded exactly as they arrive.
package httpproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/firatmio/mcp-audit-proxy/internal/interceptor"
	"github.com/firatmio/mcp-audit-proxy/internal/policy"
	"github.com/firatmio/mcp-audit-proxy/internal/sinks"
)

// maxAuditBytes caps how much of a single request or response body we buffer
// for auditing. Larger payloads are proxied untouched and logged.
const maxAuditBytes = 8 << 20 // 8 MiB

// sessionHeader is the Streamable HTTP session identifier, which we use as the
// client id when the client supplies one.
const sessionHeader = "Mcp-Session-Id"

// Config describes a Proxy.
type Config struct {
	// Target is the upstream MCP server URL, for example
	// https://example.com/mcp.
	Target string

	Interceptor *interceptor.Interceptor
	Policy      *policy.Engine
	Dispatcher  *sinks.Dispatcher
	Logger      *log.Logger
}

// Proxy is an auditing reverse proxy for a remote MCP server.
type Proxy struct {
	target      *url.URL
	interceptor *interceptor.Interceptor
	policy      *policy.Engine
	dispatcher  *sinks.Dispatcher
	logger      *log.Logger
	reverse     *httputil.ReverseProxy
}

// New builds a Proxy from cfg.
func New(cfg Config) (*Proxy, error) {
	if cfg.Target == "" {
		return nil, errors.New("no target given; usage: mcp-audit serve --target <url>")
	}
	target, err := url.Parse(cfg.Target)
	if err != nil {
		return nil, fmt.Errorf("target %q is not a valid URL: %w", cfg.Target, err)
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("target %q must start with http:// or https://", cfg.Target)
	}
	if target.Host == "" {
		return nil, fmt.Errorf("target %q is missing a host", cfg.Target)
	}
	if cfg.Interceptor == nil || cfg.Policy == nil || cfg.Dispatcher == nil {
		return nil, errors.New("http proxy is missing its audit pipeline")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.New(os.Stderr, "mcp-audit: ", 0)
	}

	p := &Proxy{
		target:      target,
		interceptor: cfg.Interceptor,
		policy:      cfg.Policy,
		dispatcher:  cfg.Dispatcher,
		logger:      logger,
	}

	p.reverse = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			// --target names the MCP endpoint itself, so every request goes
			// there whatever local path the client was configured with. That
			// keeps `--target https://host/mcp` working for a client pointed
			// at http://localhost:9000/, /mcp or /anything, instead of
			// silently producing /mcp/mcp.
			r.Out.URL.Scheme = target.Scheme
			r.Out.URL.Host = target.Host
			r.Out.URL.Path = target.Path
			r.Out.URL.RawPath = target.RawPath
			r.Out.URL.RawQuery = mergeQuery(target.RawQuery, r.In.URL.RawQuery)
			r.Out.Host = target.Host
			r.SetXForwarded()
		},
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.handleUpstreamError,
		// FlushInterval -1 flushes immediately, which is what an SSE stream
		// needs: no buffering between the MCP server and the client.
		FlushInterval: -1,
	}

	return p, nil
}

// Target returns the upstream URL being audited.
func (p *Proxy) Target() *url.URL { return p.target }

// mergeQuery combines the query string baked into the target URL with the one
// the client sent. Client parameters (session ids and the like) come last so
// they win on a duplicate key.
func mergeQuery(targetQuery, clientQuery string) string {
	switch {
	case targetQuery == "":
		return clientQuery
	case clientQuery == "":
		return targetQuery
	default:
		return targetQuery + "&" + clientQuery
	}
}

// Handler returns the http.Handler that audits and forwards MCP traffic.
func (p *Proxy) Handler() http.Handler { return p }

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientID := r.Header.Get(sessionHeader)

	if r.Body != nil && r.ContentLength != 0 {
		blocked, err := p.auditRequestBody(w, r, clientID)
		if err != nil {
			p.logger.Printf("cannot read request body: %v", err)
			http.Error(w, "mcp-audit could not read the request body", http.StatusBadRequest)
			return
		}
		if blocked {
			return
		}
	}

	p.reverse.ServeHTTP(w, r)
}

// auditRequestBody reads the JSON-RPC request, audits it, applies policy and
// restores the body so the upstream server sees exactly what the client sent.
// It reports whether the request was blocked and already answered.
func (p *Proxy) auditRequestBody(w http.ResponseWriter, r *http.Request, clientID string) (blocked bool, err error) {
	limited := io.LimitReader(r.Body, maxAuditBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return false, err
	}

	if len(body) > maxAuditBytes {
		// Too big to audit: stream it through untouched rather than hold the
		// whole thing in memory.
		p.logger.Printf("skipping audit of a request body over %d bytes", maxAuditBytes)
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
		return false, nil
	}

	// Hand the upstream request an identical, replayable body.
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	events := p.parse(interceptor.DirectionRequest, body, clientID)

	if len(events) == 1 && !interceptor.IsBatch(body) {
		if decision := p.policy.Evaluate(&events[0]); !decision.Allowed {
			p.dispatcher.DispatchAll(events)
			p.writeDenial(w, body, decision)
			return true, nil
		}
	} else {
		for i := range events {
			if decision := p.policy.Evaluate(&events[i]); !decision.Allowed {
				p.logger.Printf("policy would have blocked %q inside a JSON-RPC batch, forwarding anyway: %s",
					events[i].ToolName, decision.Reason)
			}
		}
	}

	p.dispatcher.DispatchAll(events)
	return false, nil
}

// writeDenial answers a blocked call with a JSON-RPC error.
//
// The HTTP status stays 200: MCP clients read the JSON-RPC error and surface it
// as a failed tool call, whereas a 4xx would look like a broken transport and
// hide the reason from the agent.
func (p *Proxy) writeDenial(w http.ResponseWriter, body []byte, decision policy.Decision) {
	p.logger.Printf("blocked: %s", decision.Reason)

	response, err := interceptor.NewErrorResponse(interceptor.RequestID(body),
		interceptor.CodePolicyDenied, "blocked by mcp-audit policy: "+decision.Reason)
	if err != nil {
		http.Error(w, "mcp-audit blocked this call", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(response); err != nil {
		p.logger.Printf("cannot send the policy denial to the client: %v", err)
	}
}

// modifyResponse taps the upstream response so that results are audited as the
// client reads them.
func (p *Proxy) modifyResponse(resp *http.Response) error {
	if resp.Body == nil {
		return nil
	}

	// Prefer the id the client sent. The server's own header only fills in on
	// the initialize exchange, where it is assigning the session for the
	// first time and the client does not have one yet.
	var clientID string
	if resp.Request != nil {
		clientID = resp.Request.Header.Get(sessionHeader)
	}
	if clientID == "" {
		clientID = resp.Header.Get(sessionHeader)
	}

	contentType := resp.Header.Get("Content-Type")
	var mode tapMode
	switch {
	case strings.HasPrefix(contentType, "text/event-stream"):
		mode = tapSSE
	case strings.HasPrefix(contentType, "application/json"):
		mode = tapJSON
	default:
		// Not MCP traffic (health checks, redirects, HTML error pages).
		return nil
	}

	resp.Body = newBodyTap(resp.Body, mode, maxAuditBytes, func(payload []byte) {
		events := p.parse(interceptor.DirectionResponse, payload, clientID)
		// Responses still go through the policy engine: that is where a
		// tools/list result gets checked for rug pulls and poisoned
		// descriptions. The decision is ignored on purpose — the bytes are
		// already on their way to the client, and the point is the flags the
		// engine records on the event.
		for i := range events {
			p.policy.Evaluate(&events[i])
		}
		p.dispatcher.DispatchAll(events)
	})
	return nil
}

// handleUpstreamError turns a failure to reach the MCP server into a JSON-RPC
// error the client can understand, instead of an empty 502.
func (p *Proxy) handleUpstreamError(w http.ResponseWriter, r *http.Request, err error) {
	p.logger.Printf("cannot reach MCP server %s: %v", p.target, err)

	response, buildErr := interceptor.NewErrorResponse(nil, interceptor.CodePolicyDenied,
		fmt.Sprintf("mcp-audit could not reach the MCP server at %s: %v", p.target, err))
	if buildErr != nil {
		http.Error(w, "mcp-audit could not reach the MCP server", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = w.Write(response)
}

// parse runs the interceptor, stamps the client id when the transport knows it,
// and downgrades any parse failure to a log line.
func (p *Proxy) parse(direction string, body []byte, clientID string) []interceptor.ToolCallEvent {
	events, err := p.interceptor.Parse(direction, body)
	if err != nil && !errors.Is(err, interceptor.ErrEmptyMessage) {
		p.logger.Printf("could not audit a %s body, forwarding it unchanged: %v", direction, err)
	}
	if clientID != "" {
		for i := range events {
			events[i].ClientID = clientID
		}
	}
	return events
}

// ListenAndServe runs the proxy on addr until ctx is cancelled.
func (p *Proxy) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: p,
		// No write timeout: an SSE stream is meant to stay open.
		ReadHeaderTimeout: 10 * time.Second,
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %w", addr, err)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(listener)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("proxy did not shut down cleanly: %w", err)
		}
		return nil
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("proxy stopped: %w", err)
	}
}
