package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// ToolDescriptor is one entry of an MCP `tools/list` result: the parts of a
// tool advertisement that the client's model actually reads, and that an
// attacker would therefore want to change.
type ToolDescriptor struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// Fingerprint returns a stable SHA-256 hash of everything about the tool that
// influences the model: its description and its input schema. The name is not
// hashed because it is the key the fingerprint is stored under.
//
// The schema is canonicalised first, so a server that serialises its JSON keys
// in a different order between calls does not look like an attack.
func (t ToolDescriptor) Fingerprint() string {
	h := sha256.New()
	h.Write([]byte(t.Description))
	h.Write([]byte{0})
	h.Write(canonicalJSON(t.InputSchema))
	return hex.EncodeToString(h.Sum(nil))
}

// canonicalJSON re-encodes raw with map keys in sorted order, which is what
// encoding/json does for map[string]any. Input that is not valid JSON is
// returned unchanged so it still contributes to the hash.
func canonicalJSON(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return nil
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return raw
	}
	encoded, err := json.Marshal(decoded)
	if err != nil {
		return raw
	}
	return encoded
}

// toolListResult is the shape of a `tools/list` response.
type toolListResult struct {
	Tools []ToolDescriptor `json:"tools"`
}

// ParseToolList extracts the tool advertisements from a `tools/list` result.
// A result that carries no tools array is not an error: plenty of JSON-RPC
// replies are shaped differently and simply have nothing to inspect.
func ParseToolList(result json.RawMessage) ([]ToolDescriptor, error) {
	if len(result) == 0 {
		return nil, nil
	}
	var parsed toolListResult
	if err := json.Unmarshal(result, &parsed); err != nil {
		return nil, fmt.Errorf("cannot read the tools/list result: %w", err)
	}
	return parsed.Tools, nil
}
