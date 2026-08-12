package interceptor

import (
	"bytes"
	"encoding/json"
)

// CodePolicyDenied is the JSON-RPC error code returned to a client whose tool
// call was blocked by policy. It sits in the -32000..-32099 range the spec
// reserves for implementation-defined server errors.
const CodePolicyDenied = -32000

// RequestID extracts the raw JSON-RPC id from a message without fully parsing
// it. It returns nil for notifications, batches and unreadable input.
//
// Both proxy modes need this on the (rare) denial path, to address the error
// response back at the request that caused it.
func RequestID(raw []byte) json.RawMessage {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil
	}
	var probe struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return nil
	}
	if _, ok := idKey(probe.ID); !ok {
		return nil
	}
	return probe.ID
}

// IsBatch reports whether raw is a JSON-RPC batch (a top-level array).
func IsBatch(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '['
}

// NewErrorResponse builds a JSON-RPC 2.0 error response addressed at id, ready
// to be written back to the client. The returned bytes carry no trailing
// newline; stdio callers add their own framing.
//
// id may be nil, in which case a null id is used, as the spec requires for
// errors that cannot be attributed to a request.
func NewErrorResponse(id json.RawMessage, code int, message string) ([]byte, error) {
	if len(bytes.TrimSpace(id)) == 0 {
		id = json.RawMessage("null")
	}
	return json.Marshal(rpcMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error: &rpcError{
			Code:    code,
			Message: message,
		},
	})
}
