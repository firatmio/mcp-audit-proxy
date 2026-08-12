package policy

import (
	"strings"
	"testing"

	"github.com/firatmio/mcp-audit-proxy/internal/config"
)

func TestZeroConfigAllowsEverything(t *testing.T) {
	rbac, err := NewRBAC(config.Default().Policy.RBAC)
	if err != nil {
		t.Fatalf("NewRBAC(default) error = %v", err)
	}

	if !rbac.ShadowMode() {
		t.Error("ShadowMode() = false, the out-of-the-box config must never block")
	}
	for _, tool := range []string{"read_file", "delete_everything", "", "weird/tool name"} {
		if allowed, reason := rbac.Check("any-client", tool); !allowed {
			t.Errorf("Check(any-client, %q) = denied (%s), want allowed", tool, reason)
		}
	}
}

func TestDefaultDenyBlocksUnlistedTools(t *testing.T) {
	rbac, err := NewRBAC(config.RBAC{Default: config.DecisionDeny})
	if err != nil {
		t.Fatalf("NewRBAC error = %v", err)
	}

	if rbac.ShadowMode() {
		t.Error("ShadowMode() = true for a default-deny policy")
	}
	if allowed, _ := rbac.Check("c", "read_file"); allowed {
		t.Error("Check() = allowed under default deny with no rules, want denied")
	}
}

func TestDenyWinsOverAllow(t *testing.T) {
	rbac, err := NewRBAC(config.RBAC{
		Default: config.DecisionAllow,
		Rules: []config.Rule{
			{Client: "*", Allow: []string{"*"}, Deny: []string{"delete_everything"}},
		},
	})
	if err != nil {
		t.Fatalf("NewRBAC error = %v", err)
	}

	if allowed, _ := rbac.Check("c", "delete_everything"); allowed {
		t.Error("Check(delete_everything) = allowed, deny must win over a matching allow")
	}
	if allowed, _ := rbac.Check("c", "read_file"); !allowed {
		t.Error("Check(read_file) = denied, want allowed by the wildcard allow entry")
	}
}

func TestAllowListIsExhaustive(t *testing.T) {
	rbac, err := NewRBAC(config.RBAC{
		Default: config.DecisionAllow, // deliberately permissive default
		Rules: []config.Rule{
			{Client: "ci-agent", Allow: []string{"read_file", "list_users"}},
		},
	})
	if err != nil {
		t.Fatalf("NewRBAC error = %v", err)
	}

	if allowed, _ := rbac.Check("ci-agent", "read_file"); !allowed {
		t.Error("Check(ci-agent, read_file) = denied, want allowed")
	}
	if allowed, reason := rbac.Check("ci-agent", "write_file"); allowed {
		t.Errorf("Check(ci-agent, write_file) = allowed (%s); an allow list must be exhaustive", reason)
	}
	// A client the rule does not cover falls through to the default.
	if allowed, _ := rbac.Check("other-agent", "write_file"); !allowed {
		t.Error("Check(other-agent, write_file) = denied, want the default allow to apply")
	}
}

func TestDenyRuleDoesNotRestrictOtherTools(t *testing.T) {
	rbac, err := NewRBAC(config.RBAC{
		Default: config.DecisionAllow,
		Rules: []config.Rule{
			{Client: "*", Deny: []string{"shell_*"}},
		},
	})
	if err != nil {
		t.Fatalf("NewRBAC error = %v", err)
	}

	if allowed, _ := rbac.Check("c", "shell_exec"); allowed {
		t.Error("Check(shell_exec) = allowed, want denied by the shell_* pattern")
	}
	if allowed, _ := rbac.Check("c", "read_file"); !allowed {
		t.Error("Check(read_file) = denied; a deny-only rule must not act as an allow list")
	}
}

func TestClientPatternScopesRules(t *testing.T) {
	rbac, err := NewRBAC(config.RBAC{
		Default: config.DecisionAllow,
		Rules: []config.Rule{
			{Client: "prod-*", Deny: []string{"*"}},
		},
	})
	if err != nil {
		t.Fatalf("NewRBAC error = %v", err)
	}

	if allowed, _ := rbac.Check("prod-agent-1", "read_file"); allowed {
		t.Error("Check(prod-agent-1) = allowed, want denied by the prod-* rule")
	}
	if allowed, _ := rbac.Check("dev-agent-1", "read_file"); !allowed {
		t.Error("Check(dev-agent-1) = denied, the prod-* rule must not apply")
	}
}

func TestWildcardClientCoversUnknownClientID(t *testing.T) {
	rbac, err := NewRBAC(config.RBAC{
		Default: config.DecisionAllow,
		Rules:   []config.Rule{{Client: "*", Deny: []string{"dangerous"}}},
	})
	if err != nil {
		t.Fatalf("NewRBAC error = %v", err)
	}

	// Stdio mode often cannot identify the client; "*" must still cover it.
	if allowed, _ := rbac.Check("", "dangerous"); allowed {
		t.Error("Check(\"\", dangerous) = allowed, a \"*\" client rule must cover an unknown client")
	}
}

func TestMultipleRulesCombine(t *testing.T) {
	rbac, err := NewRBAC(config.RBAC{
		Default: config.DecisionDeny,
		Rules: []config.Rule{
			{Client: "*", Allow: []string{"read_*"}},
			{Client: "admin", Allow: []string{"write_*"}},
			{Client: "*", Deny: []string{"read_secrets"}},
		},
	})
	if err != nil {
		t.Fatalf("NewRBAC error = %v", err)
	}

	cases := []struct {
		client, tool string
		want         bool
	}{
		{"admin", "read_file", true},
		{"admin", "write_file", true},
		{"guest", "write_file", false},
		{"guest", "read_file", true},
		{"admin", "read_secrets", false}, // deny wins even for admin
		{"guest", "something_else", false},
	}
	for _, tc := range cases {
		got, reason := rbac.Check(tc.client, tc.tool)
		if got != tc.want {
			t.Errorf("Check(%q, %q) = %v (%s), want %v", tc.client, tc.tool, got, reason, tc.want)
		}
	}
}

func TestNewRBACRejectsBadDefault(t *testing.T) {
	if _, err := NewRBAC(config.RBAC{Default: "maybe"}); err == nil {
		t.Fatal("NewRBAC(default: maybe) error = nil, want an error")
	}
}

func TestNewRBACTreatsEmptyDefaultAsAllow(t *testing.T) {
	rbac, err := NewRBAC(config.RBAC{})
	if err != nil {
		t.Fatalf("NewRBAC({}) error = %v", err)
	}
	if allowed, _ := rbac.Check("c", "anything"); !allowed {
		t.Error("an unset default must mean allow (shadow mode)")
	}
}

func TestCheckReasonIsHumanReadable(t *testing.T) {
	rbac, _ := NewRBAC(config.RBAC{
		Default: config.DecisionAllow,
		Rules:   []config.Rule{{Client: "*", Deny: []string{"rm_rf"}}},
	})

	_, reason := rbac.Check("agent", "rm_rf")
	if reason == "" {
		t.Fatal("Check returned an empty reason for a denial")
	}
	for _, want := range []string{"rm_rf", "denied"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason %q does not mention %q", reason, want)
		}
	}
}

func TestMatchPattern(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "anything", true},
		{"*", "", true},
		{"exact", "exact", true},
		{"exact", "exactly", false},
		{"exact", "", false},
		{"", "", true},
		{"", "x", false},
		{"read_*", "read_file", true},
		{"read_*", "read_", true},
		{"read_*", "write_file", false},
		{"*_file", "read_file", true},
		{"*_file", "read_file_x", false},
		{"a*b", "ab", true},
		{"a*b", "axxxb", true},
		{"a*b", "ba", false},
		{"a*a", "a", false},
		{"*mid*", "xxmidyy", true},
		{"*mid*", "xxxyy", false},
		{"pre*mid*post", "pre_mid_post", true},
		{"pre*mid*post", "pre_post", false},
	}

	for _, tc := range cases {
		if got := matchPattern(tc.pattern, tc.s); got != tc.want {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}
