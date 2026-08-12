package policy

import (
	"fmt"
	"strings"

	"github.com/firatmio/mcp-audit-proxy/internal/config"
)

// RBAC decides whether a given client is permitted to call a given tool.
//
// Evaluation order, for the rules whose client pattern matches:
//
//  1. If any deny pattern matches the tool, the call is denied. Deny always
//     wins — a typo in an allow list must never widen access.
//  2. Otherwise, if any allow pattern matches the tool, the call is allowed.
//  3. Otherwise, if at least one matching rule has a non-empty allow list, the
//     call is denied: an allow list is an exhaustive list.
//  4. Otherwise the configured default applies (out of the box: allow).
type RBAC struct {
	defaultAllow bool
	rules        []config.Rule
}

// NewRBAC compiles an RBAC evaluator from configuration.
func NewRBAC(cfg config.RBAC) (*RBAC, error) {
	def := strings.ToLower(strings.TrimSpace(cfg.Default))
	if def == "" {
		def = config.DecisionAllow
	}
	if def != config.DecisionAllow && def != config.DecisionDeny {
		return nil, fmt.Errorf("policy.rbac.default must be %q or %q, got %q",
			config.DecisionAllow, config.DecisionDeny, cfg.Default)
	}

	return &RBAC{
		defaultAllow: def == config.DecisionAllow,
		rules:        cfg.Rules,
	}, nil
}

// ShadowMode reports whether this evaluator can never deny anything, which is
// the zero-config default. The CLI uses it to tell the user what mode they are
// running in.
func (r *RBAC) ShadowMode() bool {
	return r.defaultAllow && len(r.rules) == 0
}

// Check reports whether clientID may call toolName, along with a
// human-readable reason suitable for a CLI message or an audit record.
func (r *RBAC) Check(clientID, toolName string) (allowed bool, reason string) {
	sawAllowList := false

	for _, rule := range r.rules {
		if !matchPattern(rule.Client, clientID) {
			continue
		}
		for _, pattern := range rule.Deny {
			if matchPattern(pattern, toolName) {
				return false, fmt.Sprintf("tool %q is denied by rule for client %q (deny: %q)",
					toolName, rule.Client, pattern)
			}
		}
		if len(rule.Allow) > 0 {
			sawAllowList = true
		}
	}

	for _, rule := range r.rules {
		if !matchPattern(rule.Client, clientID) {
			continue
		}
		for _, pattern := range rule.Allow {
			if matchPattern(pattern, toolName) {
				return true, fmt.Sprintf("tool %q is allowed by rule for client %q (allow: %q)",
					toolName, rule.Client, pattern)
			}
		}
	}

	if sawAllowList {
		return false, fmt.Sprintf("tool %q is not in the allow list for client %q", toolName, clientID)
	}
	if r.defaultAllow {
		return true, "allowed by default policy"
	}
	return false, fmt.Sprintf("tool %q is not allowed: default policy is deny", toolName)
}

// matchPattern reports whether s matches pattern, where "*" in the pattern
// stands for any run of characters (including none). Matching is exact when
// the pattern contains no wildcard.
//
// An empty pattern matches only an empty string, except that "*" matches
// everything including "" — so an unknown (empty) client id is still covered
// by a `client: "*"` rule.
func matchPattern(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}

	parts := strings.Split(pattern, "*")

	// The pattern's leading literal must sit at the start of s...
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	rest := s[len(parts[0]):]

	// ...and its trailing literal at the end.
	last := parts[len(parts)-1]
	if !strings.HasSuffix(rest, last) {
		return false
	}
	rest = rest[:len(rest)-len(last)]

	// Everything between must appear in order.
	for _, part := range parts[1 : len(parts)-1] {
		if part == "" {
			continue
		}
		idx := strings.Index(rest, part)
		if idx < 0 {
			return false
		}
		rest = rest[idx+len(part):]
	}
	return true
}
