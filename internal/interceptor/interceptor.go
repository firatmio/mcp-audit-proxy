package interceptor

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ErrEmptyMessage is returned by Parse when the input holds no JSON at all
// (blank line, whitespace only). Callers should treat it as "nothing to audit"
// rather than as a failure.
var ErrEmptyMessage = errors.New("empty message")

// defaultMaxPending caps how many in-flight requests we remember for
// request/response correlation. A misbehaving server that never answers must
// not be able to grow this map without bound.
const defaultMaxPending = 4096

// Options configures a new Interceptor.
type Options struct {
	// ServerName labels every event with the MCP server being audited.
	ServerName string
	// ClientID labels every event with the MCP client, when the transport can
	// tell us (HTTP session header, CLI flag). May be empty.
	ClientID string
	// MaxPending bounds the request-correlation table. Zero means the default.
	MaxPending int
	// Now is injectable for tests. Zero value means time.Now.
	Now func() time.Time
	// NewID is injectable for tests. Zero value means a random UUIDv4.
	NewID func() string
}

// pendingCall remembers just enough about a request to enrich its response.
type pendingCall struct {
	method   string
	toolName string
}

// Interceptor parses JSON-RPC messages into ToolCallEvents and correlates
// responses back to the requests that caused them. It is safe for concurrent
// use: the stdio wrapper feeds it from two goroutines at once.
type Interceptor struct {
	serverName string
	clientID   string
	maxPending int
	now        func() time.Time
	newID      func() string

	mu      sync.Mutex
	pending map[string]pendingCall
	order   []string // insertion order, for FIFO eviction of stale entries
}

// New creates an Interceptor from opts.
func New(opts Options) *Interceptor {
	ic := &Interceptor{
		serverName: opts.ServerName,
		clientID:   opts.ClientID,
		maxPending: opts.MaxPending,
		now:        opts.Now,
		newID:      opts.NewID,
		pending:    make(map[string]pendingCall),
	}
	if ic.maxPending <= 0 {
		ic.maxPending = defaultMaxPending
	}
	if ic.now == nil {
		ic.now = time.Now
	}
	if ic.newID == nil {
		ic.newID = NewEventID
	}
	return ic
}

// SetClientID records the client identity once the transport learns it (for
// example after an MCP "initialize" handshake or from a session header).
func (ic *Interceptor) SetClientID(id string) {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	ic.clientID = id
}

// Parse converts one raw wire payload into zero or more audit events.
//
// direction must be DirectionRequest or DirectionResponse. The payload may be
// a single JSON-RPC message or a JSON-RPC batch (top-level array); a batch
// yields one event per element.
//
// Parse never mutates raw and never takes ownership of it — callers are free
// to forward the original bytes untouched, which is exactly what both proxy
// modes do.
//
// A batch with some unparsable elements returns both the events it could read
// and a non-nil error, so callers should always consume the events they get
// even when err != nil.
func (ic *Interceptor) Parse(direction string, raw []byte) ([]ToolCallEvent, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, ErrEmptyMessage
	}

	if trimmed[0] == '[' {
		var batch []json.RawMessage
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			return nil, fmt.Errorf("malformed JSON-RPC batch: %w", err)
		}
		events := make([]ToolCallEvent, 0, len(batch))
		var firstErr error
		for _, item := range batch {
			ev, err := ic.parseOne(direction, item)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			events = append(events, ev)
		}
		if len(events) == 0 && firstErr != nil {
			return nil, firstErr
		}
		return events, firstErr
	}

	ev, err := ic.parseOne(direction, trimmed)
	if err != nil {
		return nil, err
	}
	return []ToolCallEvent{ev}, nil
}

// parseOne handles a single (non-batch) JSON-RPC message.
func (ic *Interceptor) parseOne(direction string, raw []byte) (ToolCallEvent, error) {
	var msg rpcMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return ToolCallEvent{}, fmt.Errorf("malformed JSON-RPC message: %w", err)
	}
	if msg.JSONRPC != "2.0" {
		return ToolCallEvent{}, fmt.Errorf("not a JSON-RPC 2.0 message (jsonrpc field was %q)", msg.JSONRPC)
	}

	ev := ToolCallEvent{
		Timestamp:  ic.now().UTC(),
		EventID:    ic.newID(),
		ClientID:   ic.currentClientID(),
		ServerName: ic.serverName,
		Direction:  direction,
	}

	switch {
	case msg.Method != "":
		ic.fillFromRequest(&ev, &msg)
	case msg.Result != nil || msg.Error != nil:
		ic.fillFromResponse(&ev, &msg)
	default:
		return ToolCallEvent{}, errors.New("JSON-RPC message has neither method, result nor error")
	}

	return ev, nil
}

// fillFromRequest populates an event from a request or notification, and
// remembers the call so the matching response can be enriched later.
func (ic *Interceptor) fillFromRequest(ev *ToolCallEvent, msg *rpcMessage) {
	ev.Method = msg.Method

	if msg.Method == MethodToolsCall && len(msg.Params) > 0 {
		var params toolCallParams
		// A params block we cannot read is still worth auditing, so a decode
		// failure only costs us the tool name, never the event.
		if err := json.Unmarshal(msg.Params, &params); err == nil {
			ev.ToolName = params.Name
			ev.Arguments = params.Arguments
		} else {
			ev.Arguments = msg.Params
		}
	} else {
		ev.Arguments = msg.Params
	}

	// Notifications carry no id and get no response, so nothing to correlate.
	if key, ok := idKey(msg.ID); ok {
		ic.rememberPending(key, pendingCall{method: msg.Method, toolName: ev.ToolName})
	}
}

// fillFromResponse populates an event from a result or error reply, pulling the
// method and tool name off the request it answers.
func (ic *Interceptor) fillFromResponse(ev *ToolCallEvent, msg *rpcMessage) {
	if key, ok := idKey(msg.ID); ok {
		if call, found := ic.takePending(key); found {
			ev.Method = call.method
			ev.ToolName = call.toolName
		}
	}
	ev.Result = msg.Result
	if msg.Error != nil {
		ev.Error = fmt.Sprintf("%s (code %d)", msg.Error.Message, msg.Error.Code)
	}
}

func (ic *Interceptor) currentClientID() string {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	return ic.clientID
}

// rememberPending stores a request under key, evicting the oldest entry when
// the table is full.
func (ic *Interceptor) rememberPending(key string, call pendingCall) {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	if _, exists := ic.pending[key]; !exists {
		ic.order = append(ic.order, key)
	}
	ic.pending[key] = call

	for len(ic.order) > ic.maxPending {
		oldest := ic.order[0]
		ic.order = ic.order[1:]
		delete(ic.pending, oldest)
	}
}

// takePending removes and returns the request recorded under key.
func (ic *Interceptor) takePending(key string) (pendingCall, bool) {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	call, ok := ic.pending[key]
	if !ok {
		return pendingCall{}, false
	}
	delete(ic.pending, key)
	for i, k := range ic.order {
		if k == key {
			ic.order = append(ic.order[:i], ic.order[i+1:]...)
			break
		}
	}
	return call, true
}

// idKey normalises a JSON-RPC id (string or number) into a map key. It reports
// false for absent or null ids, which mark notifications.
func idKey(raw json.RawMessage) (string, bool) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return "", false
	}
	return s, true
}

// NewEventID returns a random RFC 4122 version 4 UUID. It uses crypto/rand and
// falls back to a timestamp-derived id if the system entropy source fails, so
// that an audit event is never dropped for want of an identifier.
func NewEventID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10

	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}
