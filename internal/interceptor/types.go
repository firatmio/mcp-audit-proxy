// Package interceptor turns raw JSON-RPC 2.0 messages flowing between an MCP
// client and an MCP server into structured audit records (ToolCallEvent).
//
// It is deliberately transport-agnostic: both the stdio wrapper and the HTTP
// reverse proxy feed raw message bytes into the same Interceptor, so the
// parsing rules live in exactly one place.
package interceptor

import (
	"encoding/json"

	"github.com/firatmio/mcp-audit-proxy/pkg/event"
)

// The audit record itself lives in pkg/event, because it is the wire format
// and anything on the other end of that wire — a hosted backend, a SIEM
// adapter — needs the same definition rather than a restatement of it. These
// aliases keep the rest of this module writing interceptor.ToolCallEvent.

// ToolCallEvent is the canonical audit record. See pkg/event.
type ToolCallEvent = event.ToolCallEvent

// Direction values carried by ToolCallEvent.Direction.
const (
	DirectionRequest  = event.DirectionRequest
	DirectionResponse = event.DirectionResponse
)

// MCP JSON-RPC method names the interceptor gives special treatment.
const (
	MethodToolsCall = event.MethodToolsCall
	MethodToolsList = event.MethodToolsList
)

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
