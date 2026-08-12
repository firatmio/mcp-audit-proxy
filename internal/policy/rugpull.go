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

// Fingerprint is what we remember about one tool between runs.
type Fingerprint struct {
	Hash      string    `json:"hash"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Changes counts how many times this tool's advertisement has changed
	// since we first recorded it.
	Changes int `json:"changes"`
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

	d := &RugPullDetector{
		path:       resolved,
		serverName: serverName,
		state:      toolState{Version: stateVersion, Servers: map[string]map[string]Fingerprint{}},
	}

	raw, err := os.ReadFile(resolved)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return d, nil // first run
		}
		return nil, fmt.Errorf("cannot read the tool fingerprint store %s: %w", resolved, err)
	}
	if len(raw) == 0 {
		return d, nil
	}

	var loaded toolState
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return nil, fmt.Errorf("the tool fingerprint store %s is corrupt (delete it to start over): %w", resolved, err)
	}
	if loaded.Version != stateVersion {
		return nil, fmt.Errorf("the tool fingerprint store %s was written by a different version of mcp-audit (found version %d, expected %d); delete it to start over",
			resolved, loaded.Version, stateVersion)
	}
	if loaded.Servers == nil {
		loaded.Servers = map[string]map[string]Fingerprint{}
	}
	d.state = loaded
	return d, nil
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
	known, ok := d.state.Servers[d.serverName]
	if !ok {
		known = map[string]Fingerprint{}
		d.state.Servers[d.serverName] = known
	}

	now := time.Now().UTC()
	var changes []Change
	dirty := false

	for _, tool := range tools {
		hash := tool.Fingerprint()
		previous, seen := known[tool.Name]

		switch {
		case !seen:
			known[tool.Name] = Fingerprint{Hash: hash, FirstSeen: now, LastSeen: now}
			dirty = true
		case previous.Hash != hash:
			changes = append(changes, Change{
				Tool:      tool.Name,
				OldHash:   previous.Hash,
				NewHash:   hash,
				FirstSeen: previous.FirstSeen,
			})
			previous.Hash = hash
			previous.LastSeen = now
			previous.Changes++
			known[tool.Name] = previous
			dirty = true
		default:
			previous.LastSeen = now
			known[tool.Name] = previous
			dirty = true
		}
	}
	d.mu.Unlock()

	if !dirty {
		return changes, nil
	}
	if err := d.save(); err != nil {
		// The detection itself still stands; only the memory of it failed.
		return changes, err
	}
	return changes, nil
}

// save writes the store atomically, so a crash mid-write cannot leave a corrupt
// file that would refuse to load on the next run.
func (d *RugPullDetector) save() error {
	d.mu.Lock()
	encoded, err := json.MarshalIndent(d.state, "", "  ")
	d.mu.Unlock()
	if err != nil {
		return fmt.Errorf("cannot serialise the tool fingerprint store: %w", err)
	}

	dir := filepath.Dir(d.path)
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
	if err := os.Rename(tmpName, d.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("cannot replace the tool fingerprint store %s: %w", d.path, err)
	}
	return nil
}
