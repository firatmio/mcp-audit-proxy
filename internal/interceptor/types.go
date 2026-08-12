// Package interceptor turns raw JSON-RPC 2.0 messages flowing between an MCP
// client and an MCP server into structured audit records (ToolCallEvent).
//
// It is deliberately transport-agnostic: both the stdio wrapper and the HTTP
// reverse proxy feed raw message bytes into the same Interceptor, so the
// parsing rules live in exactly one place.
package interceptor

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

// MCP JSON-RPC method names the interceptor gives special treatment.
const (
	// MethodToolsCall is the method whose params carry a tool name and arguments.
	MethodToolsCall = "tools/call"
	// MethodToolsList is the method whose result carries tool descriptions.
	// Rug-pull detection hangs off this.
	MethodToolsList = "tools/list"
)

// ToolCallEvent is the canonical audit record produced for every JSON-RPC
// message that crosses the proxy, in either direction. It is the struct that
// gets serialised to JSONL and shipped to every other sink.
type ToolCallEvent struct {
	Timestamp   time.Time       `json:"timestamp"`
	EventID     string          `json:"event_id"`    // UUID, for idempotent ingest
	ClientID    string          `json:"client_id"`   // which MCP client, when known
	ServerName  string          `json:"server_name"` // which MCP server
	Direction   string          `json:"direction"`   // "request" | "response"
	Method      string          `json:"method"`      // JSON-RPC method name
	ToolName    string          `json:"tool_name,omitempty"`
	Arguments   json.RawMessage `json:"arguments,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"`
	Error       string          `json:"error,omitempty"`
	PolicyFlags []string        `json:"policy_flags,omitempty"` // rug_pull, poisoning_suspect, ...
}

// IsToolCall reports whether the event describes an MCP "tools/call" exchange,
// which is the only method the RBAC layer currently acts on.
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

// rpcMessage is the wire-level JSON-RPC 2.0 envelope. Every field is optional
// at the JSON level because requests, notifications, responses and errors all
// share this shape and are told apart by which fields are populated.
type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// rpcError is the JSON-RPC 2.0 error object.
type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// toolCallParams is the params shape of an MCP "tools/call" request.
type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}
