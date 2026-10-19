// Package corpus measures how often mcp-audit's detectors raise a false alarm
// on tool advertisements people actually publish.
//
// The benign set in testdata/corpus is captured from real MCP servers with
// scripts/corpus-capture, not written for the test, and every tool is run
// through the same policy.Engine the proxy uses with the default policy. The
// number this produces is the one a user will experience: how many of the tools
// they install will make mcp-audit cry wolf.
package corpus

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/firatmio/mcp-audit-proxy/internal/policy"
)

// Tool is one advertised tool, in the shape tools/list returns it.
type Tool = policy.ToolDescriptor

// BenignSet is the tool list of one real MCP server, captured with
// scripts/corpus-capture.
type BenignSet struct {
	Server     string   `json:"server"`
	Package    string   `json:"package"`
	License    string   `json:"license"`
	Repository string   `json:"repository"`
	Captured   string   `json:"captured"`
	Command    []string `json:"command"`
	Tools      []Tool   `json:"tools"`
}

// Corpus is everything under testdata/corpus.
type Corpus struct {
	Benign []BenignSet
}

// Load reads and validates the corpus rooted at dir.
func Load(dir string) (*Corpus, error) {
	c := &Corpus{}
	if err := loadDir(filepath.Join(dir, "benign"), &c.Benign); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// loadDir decodes every .json file in dir, in name order, into *out.
func loadDir[T any](dir string, out *[]T) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		var item T
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		// A misspelt field would otherwise vanish silently, and with it
		// whatever the file was meant to contribute.
		dec.DisallowUnknownFields()
		if err := dec.Decode(&item); err != nil {
			return fmt.Errorf("%s: %w", filepath.Join(dir, name), err)
		}
		*out = append(*out, item)
	}
	return nil
}

// validate rejects entries that would be silently miscounted.
func (c *Corpus) validate() error {
	servers := map[string]bool{}
	for _, b := range c.Benign {
		if b.Server == "" || b.Package == "" || b.License == "" || len(b.Tools) == 0 {
			return fmt.Errorf("benign set %q: server, package, license and tools are required", b.Server)
		}
		if servers[b.Server] {
			return fmt.Errorf("benign set %q: duplicate server", b.Server)
		}
		servers[b.Server] = true

		names := map[string]bool{}
		for _, t := range b.Tools {
			if t.Name == "" {
				return fmt.Errorf("benign set %q: a tool has no name", b.Server)
			}
			if names[t.Name] {
				return fmt.Errorf("benign set %q: duplicate tool %q", b.Server, t.Name)
			}
			names[t.Name] = true
		}
	}
	return nil
}
