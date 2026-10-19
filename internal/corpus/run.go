package corpus

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/firatmio/mcp-audit-proxy/internal/config"
	"github.com/firatmio/mcp-audit-proxy/internal/interceptor"
	"github.com/firatmio/mcp-audit-proxy/internal/policy"
)

// ToolResult is what the detectors made of one benign tool.
type ToolResult struct {
	Server  string
	Tool    string
	Flagged bool
	// Rules are the poisoning heuristics that matched, to say why a flag was
	// raised. Flagged is the headline; Rules only explains it.
	Rules []string
}

// Report is the outcome of a full run.
type Report struct {
	Benign []ToolResult
	// Servers is the number of real servers the benign tools came from.
	Servers int
}

// Run evaluates the corpus through fresh policy.Engines with the built-in
// default policy — what a user gets with no config file. stateDir holds the
// throwaway fingerprint stores; every evaluation gets its own, so nothing one
// evaluation records can affect another.
func Run(c *Corpus, stateDir string) (*Report, error) {
	r := &Report{Servers: len(c.Benign)}
	n := 0
	newEngine := func(server string) (*policy.Engine, error) {
		n++
		cfg := config.Default().Policy
		cfg.StatePath = filepath.Join(stateDir, fmt.Sprintf("store-%04d.json", n))
		return policy.New(policy.Options{Policy: cfg, ServerName: server})
	}

	// Tools are judged one at a time, so a false positive is attributed to the
	// tool that caused it rather than to its whole server.
	for _, set := range c.Benign {
		for _, tool := range set.Tools {
			eng, err := newEngine(set.Server)
			if err != nil {
				return nil, err
			}
			ev, err := listEvent(set.Server, []Tool{tool})
			if err != nil {
				return nil, fmt.Errorf("%s/%s: %w", set.Server, tool.Name, err)
			}
			eng.Evaluate(&ev)
			r.Benign = append(r.Benign, ToolResult{
				Server:  set.Server,
				Tool:    tool.Name,
				Flagged: len(ev.PolicyFlags) > 0,
				Rules:   rulesFor(tool),
			})
		}
	}

	return r, nil
}

// listEvent builds the audit event the proxy produces for a tools/list
// response advertising tools.
func listEvent(server string, tools []Tool) (interceptor.ToolCallEvent, error) {
	result, err := json.Marshal(map[string]any{"tools": tools})
	if err != nil {
		return interceptor.ToolCallEvent{}, err
	}
	return interceptor.ToolCallEvent{
		ServerName: server,
		Direction:  interceptor.DirectionResponse,
		Method:     interceptor.MethodToolsList,
		Result:     result,
	}, nil
}

// rulesFor lists, once each and sorted, the poisoning heuristics that match
// tool.
func rulesFor(tool Tool) []string {
	seen := map[string]bool{}
	for _, f := range policy.NewPoisoningScanner().Scan([]Tool{tool}) {
		seen[f.Rule] = true
	}
	rules := make([]string, 0, len(seen))
	for rule := range seen {
		rules = append(rules, rule)
	}
	sort.Strings(rules)
	return rules
}
