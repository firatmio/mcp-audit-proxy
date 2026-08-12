package sinks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/firatmio/mcp-audit-proxy/internal/config"
	"github.com/firatmio/mcp-audit-proxy/internal/interceptor"
)

// JSONL appends audit events to a local newline-delimited JSON file. It is the
// one sink that is always enabled, and the one whose failure the CLI reports
// loudly rather than swallowing.
type JSONL struct {
	path string

	mu sync.Mutex
	f  *os.File
}

// NewJSONL opens (creating it if needed) the audit log at path. A leading "~"
// is expanded and parent directories are created.
//
// Failures here are returned rather than tolerated: if we cannot write the
// local log, the user must find out at startup, not after an incident.
func NewJSONL(path string) (*JSONL, error) {
	resolved, err := config.ExpandPath(path)
	if err != nil {
		return nil, fmt.Errorf("audit log path %q is not usable: %w", path, err)
	}

	dir := filepath.Dir(resolved)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("cannot create audit log directory %s: %w", dir, err)
	}

	// 0600: an audit log holds tool arguments, which routinely contain
	// secrets. Nobody but the owner needs to read it.
	f, err := os.OpenFile(resolved, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot open audit log %s: %w", resolved, err)
	}

	return &JSONL{path: resolved, f: f}, nil
}

// Name implements Sink.
func (j *JSONL) Name() string { return "jsonl" }

// Path returns the resolved absolute path of the log file, for CLI output.
func (j *JSONL) Path() string { return j.path }

// Write appends one event as a single line.
//
// The line is marshalled first and written in one call so that concurrent
// appends cannot interleave a half-written record.
func (j *JSONL) Write(_ context.Context, event interceptor.ToolCallEvent) error {
	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("cannot serialise event %s: %w", event.EventID, err)
	}
	line = append(line, '\n')

	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil {
		return fmt.Errorf("audit log %s is closed", j.path)
	}
	if _, err := j.f.Write(line); err != nil {
		return fmt.Errorf("cannot append to audit log %s: %w", j.path, err)
	}
	return nil
}

// Close flushes and closes the underlying file.
func (j *JSONL) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil {
		return nil
	}
	f := j.f
	j.f = nil
	if err := f.Sync(); err != nil {
		// A sync failure on close is worth reporting but the close still
		// has to happen.
		_ = f.Close()
		return fmt.Errorf("cannot flush audit log %s: %w", j.path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("cannot close audit log %s: %w", j.path, err)
	}
	return nil
}
