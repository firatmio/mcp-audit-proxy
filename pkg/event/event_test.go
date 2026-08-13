package event

import (
	"encoding/json"
	"testing"
	"time"
)

// TestWireFormatIsStable pins the JSON contract.
//
// This type is public precisely so that other programs can decode what
// mcp-audit writes. Renaming a field here would silently break every one of
// them, and nothing else in the test suite would notice — so this test exists
// to make that change loud. If it fails, the question is not "how do I update
// the expectation" but "am I breaking consumers".
func TestWireFormatIsStable(t *testing.T) {
	ev := ToolCallEvent{
		Timestamp:   time.Date(2026, 8, 13, 9, 30, 0, 0, time.UTC),
		EventID:     "0f1e2d3c-4b5a-4968-8776-655443322110",
		ClientID:    "session-abc",
		ServerName:  "filesystem",
		Direction:   DirectionRequest,
		Method:      MethodToolsCall,
		ToolName:    "read_file",
		Arguments:   json.RawMessage(`{"path":"/etc/hosts"}`),
		Result:      json.RawMessage(`{"ok":true}`),
		Error:       "boom (code -32000)",
		PolicyFlags: []string{FlagRBACDenied},
	}

	encoded, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}

	const want = `{"timestamp":"2026-08-13T09:30:00Z",` +
		`"event_id":"0f1e2d3c-4b5a-4968-8776-655443322110",` +
		`"client_id":"session-abc",` +
		`"server_name":"filesystem",` +
		`"direction":"request",` +
		`"method":"tools/call",` +
		`"tool_name":"read_file",` +
		`"arguments":{"path":"/etc/hosts"},` +
		`"result":{"ok":true},` +
		`"error":"boom (code -32000)",` +
		`"policy_flags":["rbac_denied"]}`

	if string(encoded) != want {
		t.Errorf("the wire format changed.\n got: %s\nwant: %s", encoded, want)
	}
}

func TestOptionalFieldsAreOmitted(t *testing.T) {
	// A minimal event should not carry empty keys: the local log is one line
	// per message and consumers should not have to distinguish "absent" from
	// "present but empty".
	ev := ToolCallEvent{
		Timestamp:  time.Date(2026, 8, 13, 9, 30, 0, 0, time.UTC),
		EventID:    "x",
		ServerName: "s",
		Direction:  DirectionRequest,
		Method:     "initialize",
	}

	encoded, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	for _, absent := range []string{"tool_name", "arguments", "result", "error", "policy_flags"} {
		if _, ok := decoded[absent]; ok {
			t.Errorf("key %q should be omitted when unset: %s", absent, encoded)
		}
	}
	// client_id is always present even when empty: consumers group by it.
	if _, ok := decoded["client_id"]; !ok {
		t.Errorf("client_id should always be present: %s", encoded)
	}
}

func TestRoundTrip(t *testing.T) {
	original := ToolCallEvent{
		Timestamp:   time.Date(2026, 8, 13, 9, 30, 0, 0, time.UTC),
		EventID:     "id",
		Direction:   DirectionResponse,
		Method:      MethodToolsList,
		Arguments:   json.RawMessage(`{"a":1}`),
		PolicyFlags: []string{FlagRugPull, FlagPoisoningSuspect},
	}

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	var decoded ToolCallEvent
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	if !decoded.Timestamp.Equal(original.Timestamp) {
		t.Errorf("Timestamp = %v, want %v", decoded.Timestamp, original.Timestamp)
	}
	if !decoded.HasFlag(FlagRugPull) || !decoded.HasFlag(FlagPoisoningSuspect) {
		t.Errorf("PolicyFlags = %v, want both flags preserved", decoded.PolicyFlags)
	}
	if !decoded.Flagged() {
		t.Error("Flagged() = false for an event carrying flags")
	}
}

func TestHelpers(t *testing.T) {
	ev := ToolCallEvent{Method: MethodToolsCall}
	if !ev.IsToolCall() {
		t.Error("IsToolCall() = false for tools/call")
	}
	if ev.Flagged() {
		t.Error("Flagged() = true for an event with no flags")
	}

	ev.AddFlag(FlagRugPull)
	ev.AddFlag(FlagRugPull)
	if len(ev.PolicyFlags) != 1 {
		t.Errorf("PolicyFlags = %v, want the duplicate collapsed", ev.PolicyFlags)
	}
	if ev.HasFlag(FlagPoisoningSuspect) {
		t.Error("HasFlag reported a flag that was never added")
	}
}
