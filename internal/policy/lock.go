package policy

import (
	"fmt"
	"sort"
	"time"

	"github.com/firatmio/mcp-audit-proxy/internal/config"
)

// LockStore is the command-line view of the fingerprint store: what is
// approved, what is waiting for a decision, and the act of approving it.
//
// It is the "package-lock" half of the rug-pull defence. The proxy records
// what each tool looked like when a person accepted it; anything that differs
// stays flagged until `mcp-audit lock approve` says otherwise.
type LockStore struct {
	path string
}

// OpenLockStore resolves the store path. It does not read the file, so a
// missing store is reported by the operation that needs it.
func OpenLockStore(path string) (*LockStore, error) {
	resolved, err := config.ExpandPath(path)
	if err != nil {
		return nil, fmt.Errorf("tool fingerprint store path %q is not usable: %w", path, err)
	}
	return &LockStore{path: resolved}, nil
}

// Path returns the resolved location of the store, for CLI output.
func (s *LockStore) Path() string { return s.path }

// PendingChange is one tool whose current advertisement has not been approved.
type PendingChange struct {
	Server string
	Tool   string

	ApprovedHash string
	PendingHash  string
	// Approved and Pending are nil when the store predates snapshots; the CLI
	// then shows the hashes only.
	Approved *ToolSnapshot
	Pending  *ToolSnapshot

	FirstSeen    time.Time
	PendingSince time.Time
}

// Diff renders what changed between the approved and the pending version.
func (p PendingChange) Diff() []DiffLine { return DiffSnapshots(p.Approved, p.Pending) }

// Summary counts what the store holds.
type Summary struct {
	Servers int
	Tools   int
	Pending int
}

// Summary reports how many servers and tools are recorded and how many are
// waiting for approval.
func (s *LockStore) Summary() (Summary, error) {
	state, err := readStateFile(s.path)
	if err != nil {
		return Summary{}, err
	}
	var sum Summary
	for _, tools := range state.Servers {
		sum.Servers++
		for _, fp := range tools {
			sum.Tools++
			if fp.PendingHash != "" {
				sum.Pending++
			}
		}
	}
	return sum, nil
}

// Pending lists every unapproved change, ordered by server and tool so the
// output is stable.
func (s *LockStore) Pending() ([]PendingChange, error) {
	state, err := readStateFile(s.path)
	if err != nil {
		return nil, err
	}

	var out []PendingChange
	for server, tools := range state.Servers {
		for name, fp := range tools {
			if fp.PendingHash == "" {
				continue
			}
			change := PendingChange{
				Server:       server,
				Tool:         name,
				ApprovedHash: fp.Hash,
				PendingHash:  fp.PendingHash,
				Approved:     fp.Snapshot,
				Pending:      fp.PendingSnapshot,
				FirstSeen:    fp.FirstSeen,
			}
			if fp.PendingSince != nil {
				change.PendingSince = *fp.PendingSince
			}
			out = append(out, change)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Server != out[j].Server {
			return out[i].Server < out[j].Server
		}
		return out[i].Tool < out[j].Tool
	})
	return out, nil
}

// Approve accepts the pending version of tools as the new baseline and returns
// how many tools it moved.
//
// An empty server means every server; an empty tool means every tool of that
// server. Naming a server or tool that is not in the store is an error rather
// than a silent no-op, because "approved nothing" looks the same as "approved
// it" to someone who mistyped.
func (s *LockStore) Approve(server, tool string) ([]PendingChange, error) {
	state, err := readStateFile(s.path)
	if err != nil {
		return nil, err
	}

	if server != "" {
		tools, ok := state.Servers[server]
		if !ok {
			return nil, fmt.Errorf("server %q is not in %s", server, s.path)
		}
		if tool != "" {
			if _, ok := tools[tool]; !ok {
				return nil, fmt.Errorf("server %q has no recorded tool %q", server, tool)
			}
		}
	}

	var approved []PendingChange
	for serverName, tools := range state.Servers {
		if server != "" && serverName != server {
			continue
		}
		for name, fp := range tools {
			if tool != "" && name != tool {
				continue
			}
			if fp.PendingHash == "" {
				continue
			}
			approved = append(approved, PendingChange{
				Server:       serverName,
				Tool:         name,
				ApprovedHash: fp.Hash,
				PendingHash:  fp.PendingHash,
				Approved:     fp.Snapshot,
				Pending:      fp.PendingSnapshot,
			})
			fp.Hash = fp.PendingHash
			fp.Snapshot = fp.PendingSnapshot
			fp.clearPending()
			tools[name] = fp
		}
	}

	if len(approved) == 0 {
		return nil, nil
	}
	if err := writeStateFile(s.path, state); err != nil {
		return nil, err
	}

	sort.Slice(approved, func(i, j int) bool {
		if approved[i].Server != approved[j].Server {
			return approved[i].Server < approved[j].Server
		}
		return approved[i].Tool < approved[j].Tool
	})
	return approved, nil
}
