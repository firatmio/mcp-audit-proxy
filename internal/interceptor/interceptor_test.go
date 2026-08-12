package interceptor

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestInterceptor builds an Interceptor with deterministic clock and ids so
// that assertions can compare whole events.
func newTestInterceptor() *Interceptor {
	var n int
	return New(Options{
		ServerName: "test-server",
		ClientID:   "test-client",
		Now:        func() time.Time { return time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC) },
		NewID: func() string {
			n++
			return "id-" + string(rune('0'+n))
		},
	})
}

// parseSingle is a helper for the common "one message in, one event out" case.
func parseSingle(t *testing.T, ic *Interceptor, direction, raw string) ToolCallEvent {
	t.Helper()
	events, err := ic.Parse(direction, []byte(raw))
	if err != nil {
		t.Fatalf("Parse(%q) returned unexpected error: %v", raw, err)
	}
	if len(events) != 1 {
		t.Fatalf("Parse(%q) returned %d events, want 1", raw, len(events))
	}
	return events[0]
}

func TestParseToolsCallRequest(t *testing.T) {
	ic := newTestInterceptor()
	raw := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"}}}`

	ev := parseSingle(t, ic, DirectionRequest, raw)

	if ev.Direction != DirectionRequest {
		t.Errorf("Direction = %q, want %q", ev.Direction, DirectionRequest)
	}
	if ev.Method != MethodToolsCall {
		t.Errorf("Method = %q, want %q", ev.Method, MethodToolsCall)
	}
	if ev.ToolName != "read_file" {
		t.Errorf("ToolName = %q, want %q", ev.ToolName, "read_file")
	}
	if got := string(ev.Arguments); got != `{"path":"/etc/passwd"}` {
		t.Errorf("Arguments = %s, want {\"path\":\"/etc/passwd\"}", got)
	}
	if ev.ServerName != "test-server" || ev.ClientID != "test-client" {
		t.Errorf("identity fields = (%q, %q), want (test-server, test-client)", ev.ServerName, ev.ClientID)
	}
	if ev.EventID == "" {
		t.Error("EventID is empty, every event must be identifiable")
	}
	if !ev.IsToolCall() {
		t.Error("IsToolCall() = false, want true")
	}
}

func TestParseNonToolMethodKeepsParams(t *testing.T) {
	ic := newTestInterceptor()
	raw := `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///secret"}}`

	ev := parseSingle(t, ic, DirectionRequest, raw)

	if ev.Method != "resources/read" {
		t.Errorf("Method = %q, want resources/read", ev.Method)
	}
	if ev.ToolName != "" {
		t.Errorf("ToolName = %q, want empty for a non tools/call method", ev.ToolName)
	}
	if got := string(ev.Arguments); got != `{"uri":"file:///secret"}` {
		t.Errorf("Arguments = %s, want the raw params block", got)
	}
}

func TestParseNotificationHasNoCorrelation(t *testing.T) {
	ic := newTestInterceptor()
	raw := `{"jsonrpc":"2.0","method":"notifications/initialized"}`

	ev := parseSingle(t, ic, DirectionRequest, raw)

	if ev.Method != "notifications/initialized" {
		t.Errorf("Method = %q, want notifications/initialized", ev.Method)
	}
	ic.mu.Lock()
	pending := len(ic.pending)
	ic.mu.Unlock()
	if pending != 0 {
		t.Errorf("pending correlation entries = %d, want 0 for a notification", pending)
	}
}

func TestResponseIsCorrelatedToRequest(t *testing.T) {
	ic := newTestInterceptor()
	parseSingle(t, ic, DirectionRequest,
		`{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"list_users","arguments":{}}}`)

	ev := parseSingle(t, ic, DirectionResponse,
		`{"jsonrpc":"2.0","id":42,"result":{"content":[{"type":"text","text":"ok"}]}}`)

	if ev.Direction != DirectionResponse {
		t.Errorf("Direction = %q, want %q", ev.Direction, DirectionResponse)
	}
	if ev.Method != MethodToolsCall {
		t.Errorf("Method = %q, want the method of the request it answers", ev.Method)
	}
	if ev.ToolName != "list_users" {
		t.Errorf("ToolName = %q, want list_users", ev.ToolName)
	}
	if !strings.Contains(string(ev.Result), `"content"`) {
		t.Errorf("Result = %s, want the raw result block", ev.Result)
	}

	ic.mu.Lock()
	pending := len(ic.pending)
	ic.mu.Unlock()
	if pending != 0 {
		t.Errorf("pending entries after correlation = %d, want 0", pending)
	}
}

func TestResponseWithStringID(t *testing.T) {
	ic := newTestInterceptor()
	parseSingle(t, ic, DirectionRequest,
		`{"jsonrpc":"2.0","id":"abc-1","method":"tools/call","params":{"name":"echo"}}`)

	ev := parseSingle(t, ic, DirectionResponse, `{"jsonrpc":"2.0","id":"abc-1","result":{}}`)

	if ev.ToolName != "echo" {
		t.Errorf("ToolName = %q, want echo (string ids must correlate too)", ev.ToolName)
	}
}

func TestNumericAndStringIDsDoNotCollide(t *testing.T) {
	ic := newTestInterceptor()
	parseSingle(t, ic, DirectionRequest,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"numeric_tool"}}`)
	parseSingle(t, ic, DirectionRequest,
		`{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"string_tool"}}`)

	ev := parseSingle(t, ic, DirectionResponse, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	if ev.ToolName != "numeric_tool" {
		t.Errorf("ToolName = %q, want numeric_tool", ev.ToolName)
	}
	ev = parseSingle(t, ic, DirectionResponse, `{"jsonrpc":"2.0","id":"1","result":{}}`)
	if ev.ToolName != "string_tool" {
		t.Errorf("ToolName = %q, want string_tool", ev.ToolName)
	}
}

func TestErrorResponseIsRecorded(t *testing.T) {
	ic := newTestInterceptor()
	parseSingle(t, ic, DirectionRequest,
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"delete_everything"}}`)

	ev := parseSingle(t, ic, DirectionResponse,
		`{"jsonrpc":"2.0","id":9,"error":{"code":-32601,"message":"Method not found"}}`)

	if ev.Error == "" {
		t.Fatal("Error is empty, want the JSON-RPC error rendered as text")
	}
	if !strings.Contains(ev.Error, "Method not found") || !strings.Contains(ev.Error, "-32601") {
		t.Errorf("Error = %q, want it to mention both message and code", ev.Error)
	}
	if ev.ToolName != "delete_everything" {
		t.Errorf("ToolName = %q, want the tool of the failed call", ev.ToolName)
	}
}

func TestUncorrelatedResponseStillProducesEvent(t *testing.T) {
	ic := newTestInterceptor()

	ev := parseSingle(t, ic, DirectionResponse, `{"jsonrpc":"2.0","id":1234,"result":{"ok":true}}`)

	if ev.Method != "" {
		t.Errorf("Method = %q, want empty when the request was never seen", ev.Method)
	}
	if string(ev.Result) != `{"ok":true}` {
		t.Errorf("Result = %s, want the raw result even without correlation", ev.Result)
	}
}

func TestParseBatch(t *testing.T) {
	ic := newTestInterceptor()
	raw := `[
		{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a"}},
		{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"b"}}
	]`

	events, err := ic.Parse(DirectionRequest, []byte(raw))
	if err != nil {
		t.Fatalf("Parse(batch) error = %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(events))
	}
	if events[0].ToolName != "a" || events[1].ToolName != "b" {
		t.Errorf("tool names = (%q, %q), want (a, b)", events[0].ToolName, events[1].ToolName)
	}
	if events[0].EventID == events[1].EventID {
		t.Error("batch elements share an EventID, they must be individually identifiable")
	}
}

func TestParseBatchWithBadElementKeepsGoodOnes(t *testing.T) {
	ic := newTestInterceptor()
	raw := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a"}},{"not":"jsonrpc"}]`

	events, err := ic.Parse(DirectionRequest, []byte(raw))
	if err == nil {
		t.Error("Parse returned nil error, want a partial-failure error")
	}
	if len(events) != 1 || events[0].ToolName != "a" {
		t.Fatalf("events = %+v, want the one readable element", events)
	}
}

func TestParseRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"not json", `this is not json at all`},
		{"truncated json", `{"jsonrpc":"2.0","id":1,`},
		{"wrong version", `{"jsonrpc":"1.0","id":1,"method":"tools/call"}`},
		{"missing version", `{"id":1,"method":"tools/call"}`},
		{"no method result or error", `{"jsonrpc":"2.0","id":1}`},
		{"json but not an object", `"just a string"`},
		{"malformed batch", `[{"jsonrpc":"2.0"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ic := newTestInterceptor()
			events, err := ic.Parse(DirectionRequest, []byte(tc.raw))
			if err == nil {
				t.Fatalf("Parse(%q) error = nil, want an error", tc.raw)
			}
			if len(events) != 0 {
				t.Errorf("Parse(%q) returned %d events, want 0", tc.raw, len(events))
			}
		})
	}
}

func TestParseEmptyMessage(t *testing.T) {
	ic := newTestInterceptor()
	for _, raw := range []string{"", "   ", "\n", "\r\n"} {
		events, err := ic.Parse(DirectionRequest, []byte(raw))
		if !errors.Is(err, ErrEmptyMessage) {
			t.Errorf("Parse(%q) error = %v, want ErrEmptyMessage", raw, err)
		}
		if len(events) != 0 {
			t.Errorf("Parse(%q) returned events for blank input", raw)
		}
	}
}

func TestToolsCallWithUnreadableParamsStillAudited(t *testing.T) {
	ic := newTestInterceptor()
	// params is a valid JSON value but not the object tools/call expects.
	raw := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":["unexpected"]}`

	ev := parseSingle(t, ic, DirectionRequest, raw)

	if ev.Method != MethodToolsCall {
		t.Errorf("Method = %q, want tools/call even with odd params", ev.Method)
	}
	if string(ev.Arguments) != `["unexpected"]` {
		t.Errorf("Arguments = %s, want the raw params preserved", ev.Arguments)
	}
}

func TestPendingTableIsBounded(t *testing.T) {
	ic := New(Options{ServerName: "s", MaxPending: 4})

	for i := 0; i < 100; i++ {
		msg, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      i,
			"method":  "tools/call",
			"params":  map[string]string{"name": "t"},
		})
		if _, err := ic.Parse(DirectionRequest, msg); err != nil {
			t.Fatalf("Parse error: %v", err)
		}
	}

	ic.mu.Lock()
	got := len(ic.pending)
	order := len(ic.order)
	ic.mu.Unlock()
	if got > 4 || order > 4 {
		t.Errorf("pending table grew to (map %d, order %d), want at most 4", got, order)
	}
}

func TestParseIsConcurrencySafe(t *testing.T) {
	ic := New(Options{ServerName: "s"})
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = ic.Parse(DirectionRequest,
				[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`))
		}()
		go func() {
			defer wg.Done()
			_, _ = ic.Parse(DirectionResponse, []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		}()
	}
	wg.Wait()
}

func TestEventIDLooksLikeUUIDv4(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := NewEventID()
		if len(id) != 36 {
			t.Fatalf("NewEventID() = %q, want 36 characters", id)
		}
		if id[14] != '4' {
			t.Fatalf("NewEventID() = %q, want version nibble 4", id)
		}
		if seen[id] {
			t.Fatalf("NewEventID() produced a duplicate: %q", id)
		}
		seen[id] = true
	}
}

func TestAddFlagDeduplicates(t *testing.T) {
	ev := ToolCallEvent{}
	ev.AddFlag("rug_pull")
	ev.AddFlag("rug_pull")
	ev.AddFlag("poisoning_suspect")

	if len(ev.PolicyFlags) != 2 {
		t.Errorf("PolicyFlags = %v, want 2 unique flags", ev.PolicyFlags)
	}
}

func TestEventSerialisesToExpectedJSONShape(t *testing.T) {
	ic := newTestInterceptor()
	ev := parseSingle(t, ic, DirectionRequest,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi"}}}`)

	encoded, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("json.Marshal(event) error = %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("round-trip unmarshal error = %v", err)
	}
	for _, key := range []string{"timestamp", "event_id", "client_id", "server_name", "direction", "method", "tool_name", "arguments"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("serialised event is missing key %q: %s", key, encoded)
		}
	}
	// Optional fields must stay out of the log line when unset.
	if _, ok := decoded["result"]; ok {
		t.Errorf("request event should not carry a result key: %s", encoded)
	}
}
