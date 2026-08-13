// Package event defines the audit record mcp-audit produces.
//
// This is the wire format: every line of the local JSONL log, every webhook
// body, and every element of a hosted-ingest batch is one of these serialised
// to JSON. It lives in pkg/ rather than internal/ precisely so that the things
// on the other end of those wires — a hosted backend, a SIEM adapter, someone
// else's tooling — can share the definition instead of restating it and hoping
// the two stay in step.
//
// Treat the JSON tags as a public contract. Adding a field is safe; renaming
// or removing one is not.
package event

import (
	"encoding/json"
	"time"
)

// Direction values carried by ToolCallEvent.Direction.
const (
	// DirectionRequest marks a message travelling from client to server.
	DirectionRequest = "request"
	// DirectionResponse marks a message travelling from server to client.
	DirectionResponse = "response"
)

// MCP JSON-RPC method names that get special treatment.
const (
	// MethodToolsCall is the method whose params carry a tool name and
	// arguments.
	MethodToolsCall = "tools/call"
	// MethodToolsList is the method whose result carries tool descriptions.
	MethodToolsList = "tools/list"
)

// Policy flags that may appear in ToolCallEvent.PolicyFlags.
const (
	// FlagRBACDenied marks a tool call the RBAC rules refused.
	FlagRBACDenied = "rbac_denied"
	// FlagRugPull marks a tools/list result in which a previously recorded
	// tool changed its description or schema.
	FlagRugPull = "rug_pull"
	// FlagPoisoningSuspect marks a tools/list result carrying a tool
	// description that looks like a prompt-injection attempt.
	FlagPoisoningSuspect = "poisoning_suspect"
)

// ToolCallEvent is the audit record produced for every JSON-RPC message that
// crosses the proxy, in either direction.
type ToolCallEvent struct {
	Timestamp time.Time `json:"timestamp"`
	// EventID is a UUID. Consumers should treat it as the idempotency key:
	// a retried delivery carries the id it carried the first time.
	EventID string `json:"event_id"`
	// ClientID identifies the MCP client when the transport knows it — the
	// session id in HTTP mode, a CLI flag in stdio mode. Often empty.
	ClientID string `json:"client_id"`
	// ServerName identifies the MCP server being audited.
	ServerName string `json:"server_name"`
	// Direction is DirectionRequest or DirectionResponse.
	Direction string `json:"direction"`
	// Method is the JSON-RPC method name. On a response it is the method of
	// the request being answered, when that request was seen.
	Method string `json:"method"`
	// ToolName is set for tools/call exchanges.
	ToolName string `json:"tool_name,omitempty"`
	// Arguments holds the request params verbatim.
	Arguments json.RawMessage `json:"arguments,omitempty"`
	// Result holds the response result verbatim.
	Result json.RawMessage `json:"result,omitempty"`
	// Error is a rendering of the JSON-RPC error, when the response carried
	// one.
	Error string `json:"error,omitempty"`
	// PolicyFlags records what the policy engine noticed. Empty means
	// nothing was flagged.
	PolicyFlags []string `json:"policy_flags,omitempty"`
}

// IsToolCall reports whether the event describes an MCP "tools/call" exchange.
func (e *ToolCallEvent) IsToolCall() bool {
	return e.Method == MethodToolsCall
}

// AddFlag appends a policy flag once, keeping PolicyFlags free of duplicates.
func (e *ToolCallEvent) AddFlag(flag string) {
	for _, existing := range e.PolicyFlags {
		if existing == flag {
			return
		}
	}
	e.PolicyFlags = append(e.PolicyFlags, flag)
}

// HasFlag reports whether the event carries the given policy flag.
func (e *ToolCallEvent) HasFlag(flag string) bool {
	for _, existing := range e.PolicyFlags {
		if existing == flag {
			return true
		}
	}
	return false
}

// Flagged reports whether the policy engine noticed anything at all. Consumers
// that only care about alerts — a chat webhook, an alerting rule — filter on
// this.
func (e *ToolCallEvent) Flagged() bool {
	return len(e.PolicyFlags) > 0
}
