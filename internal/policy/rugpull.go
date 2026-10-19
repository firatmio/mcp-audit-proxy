package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/firatmio/mcp-audit-proxy/internal/config"
)

// A rug pull is when an MCP server advertises a harmless tool, waits for the
// user to approve it, and later changes the description or schema the model
// reads — turning an approved tool into something else without ever asking
// again. Detecting it means remembering what each tool looked like the first
// time we saw it, which is why this state has to outlive the process.

// stateVersion guards the on-disk format against future changes.
const stateVersion = 1

// ToolSnapshot is the readable text of a tool advertisement: the parts the
// model reads. The hash proves that something changed; the snapshot lets a human
// see what.
type ToolSnapshot struct {
	Description string `json:"description"`
	// InputSchema is stored canonicalised, so two snapshots of the same schema
	// compare and diff cleanly.
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

// snapshotOf records the readable parts of a tool advertisement.
func snapshotOf(t ToolDescriptor) *ToolSnapshot {
	return &ToolSnapshot{
		Description: t.Description,
		InputSchema: json.RawMessage(canonicalJSON(t.InputSchema)),
	}
}

// Fingerprint is what we remember about one tool between runs.
//
// Hash is the approved baseline: the version a person has accepted, either
// implicitly by connecting to the server for the first time or explicitly with
// `mcp-audit lock approve`. It only ever moves forward by approval. A tool that
// has since changed keeps its old Hash, and the new version waits in Pending*
// until someone approves it, so the alarm is repeated until a human has looked.
type Fingerprint struct {
	Hash      string    `json:"hash"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Changes counts how many distinct changed versions of this tool have been
	// seen since we first recorded it.
	Changes int `json:"changes"`

	// Snapshot is the readable text behind Hash. It is absent in stores written
	// before snapshots existed, and is filled in the next time the tool is seen
	// unchanged.
	Snapshot *ToolSnapshot `json:"snapshot,omitempty"`

	// PendingHash is the latest unapproved version of the tool, if it currently
	// differs from the baseline. Empty when the tool matches the baseline.
	PendingHash     string        `json:"pending_hash,omitempty"`
	PendingSnapshot *ToolSnapshot `json:"pending_snapshot,omitempty"`
	// PendingSince is when the pending version was first seen.
	PendingSince *time.Time `json:"pending_since,omitempty"`
}

// clearPending forgets an unapproved version, used when the tool has gone back
// to the approved one.
func (f *Fingerprint) clearPending() {
	f.PendingHash = ""
	f.PendingSnapshot = nil
	f.PendingSince = nil
}

// toolState is the on-disk document: server name -> tool name -> fingerprint.
type toolState struct {
	Version int                               `json:"version"`
	Servers map[string]map[string]Fingerprint `json:"servers"`
}

// Change describes one tool whose advertisement differs from the recorded one.
type Change struct {
	Tool    string
	OldHash string
	NewHash string
	// FirstSeen is when the original version was recorded, which is the fact
	// that makes a change suspicious rather than merely new.
	FirstSeen time.Time
}

// String renders a change for a CLI warning.
func (c Change) String() string {
	return fmt.Sprintf("tool %q changed its description or schema (first seen %s, hash %s -> %s)",
		c.Tool, c.FirstSeen.Format(time.RFC3339), short(c.OldHash), short(c.NewHash))
}

func short(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}

// RugPullDetector remembers tool fingerprints across runs and reports when one
// changes.
//
// It is safe for concurrent use, though in practice only the response pump
// touches it.
type RugPullDetector struct {
	path       string
	serverName string

	mu    sync.Mutex
	state toolState
}

// NewRugPullDetector loads the fingerprint store at path, creating an empty one
// if it does not exist yet. A store we cannot read is an error: silently
// starting from a blank slate would disarm the detector exactly when it
// mattered.
func NewRugPullDetector(path, serverName string) (*RugPullDetector, error) {
	resolved, err := config.ExpandPath(path)
	if err != nil {
		return nil, fmt.Errorf("tool fingerprint store path %q is not usable: %w", path, err)
	}

	state, err := readStateFile(resolved)
	if err != nil {
		return nil, err
	}
	return &RugPullDetector{path: resolved, serverName: serverName, state: state}, nil
}

// readStateFile loads the fingerprint store at an already-resolved path. A
// missing or empty file is a first run and yields an empty store; anything we
// cannot read is an error, never a silent reset.
func readStateFile(resolved string) (toolState, error) {
	empty := toolState{Version: stateVersion, Servers: map[string]map[string]Fingerprint{}}

	raw, err := os.ReadFile(resolved)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return empty, nil // first run
		}
		return toolState{}, fmt.Errorf("cannot read the tool fingerprint store %s: %w", resolved, err)
	}
	if len(raw) == 0 {
		return empty, nil
	}

	var loaded toolState
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return toolState{}, fmt.Errorf("the tool fingerprint store %s is corrupt (delete it to start over): %w", resolved, err)
	}
	if loaded.Version != stateVersion {
		return toolState{}, fmt.Errorf("the tool fingerprint store %s was written by a different version of mcp-audit (found version %d, expected %d); delete it to start over",
			resolved, loaded.Version, stateVersion)
	}
	if loaded.Servers == nil {
		loaded.Servers = map[string]map[string]Fingerprint{}
	}
	return loaded, nil
}

// Path returns the resolved location of the fingerprint store, for CLI output.
func (d *RugPullDetector) Path() string { return d.path }

// Inspect compares an advertised tool list against what was recorded, updates
// the store and returns the tools that changed.
//
// A tool seen for the first time is recorded and reported as no change: there
// is nothing suspicious about a tool existing. Only a tool that used to look
// different is a rug pull.
func (d *RugPullDetector) Inspect(tools []ToolDescriptor) ([]Change, error) {
	if len(tools) == 0 {
		return nil, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Re-read the store every time. `mcp-audit lock approve` runs as a separate
	// process and edits this file while the proxy is alive; working from a copy
	// loaded at startup would overwrite that approval on the next save.
	state, err := readStateFile(d.path)
	if err != nil {
		return nil, err
	}
	d.state = state

	known, ok := d.state.Servers[d.serverName]
	if !ok {
		known = map[string]Fingerprint{}
		d.state.Servers[d.serverName] = known
	}

	now := time.Now().UTC()
	var changes []Change

	for _, tool := range tools {
		hash := tool.Fingerprint()
		fp, seen := known[tool.Name]

		switch {
		case !seen:
			known[tool.Name] = Fingerprint{
				Hash: hash, FirstSeen: now, LastSeen: now,
				Snapshot: snapshotOf(tool),
			}
			continue

		case fp.Hash == hash:
			// Back to (or still at) the approved version. A pending change that
			// has been reverted no longer needs a decision.
			fp.clearPending()
			if fp.Snapshot == nil {
				fp.Snapshot = snapshotOf(tool)
			}

		default:
			// Different from what a person approved. The baseline stays put, so
			// the next session raises the alarm again until someone approves it.
			if fp.PendingHash != hash {
				fp.PendingHash = hash
				fp.PendingSnapshot = snapshotOf(tool)
				since := now
				fp.PendingSince = &since
				fp.Changes++
			}
			changes = append(changes, Change{
				Tool:      tool.Name,
				OldHash:   fp.Hash,
				NewHash:   hash,
				FirstSeen: fp.FirstSeen,
			})
		}

		fp.LastSeen = now
		known[tool.Name] = fp
	}

	if err := writeStateFile(d.path, d.state); err != nil {
		// The detection itself still stands; only the memory of it failed.
		return changes, err
	}
	return changes, nil
}

// writeStateFile writes the store atomically, so a crash mid-write cannot leave
// a corrupt file that would refuse to load on the next run.
func writeStateFile(path string, state toolState) error {
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot serialise the tool fingerprint store: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("cannot create the tool fingerprint directory %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".tools-*.json")
	if err != nil {
		return fmt.Errorf("cannot write the tool fingerprint store: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(encoded); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("cannot write the tool fingerprint store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("cannot write the tool fingerprint store: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("cannot replace the tool fingerprint store %s: %w", path, err)
	}
	return nil
}
