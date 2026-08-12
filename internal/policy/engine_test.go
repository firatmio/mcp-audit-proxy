package policy

import (
	"path/filepath"
	"testing"

	"github.com/firatmio/mcp-audit-proxy/internal/config"
	"github.com/firatmio/mcp-audit-proxy/internal/interceptor"
)

// newEngine builds an Engine whose persistent state lives in the test's temp
// directory, so no test ever touches the developer's real ~/.mcp-audit state.
func newEngine(t *testing.T, policyCfg config.Policy) *Engine {
	t.Helper()
	if policyCfg.StatePath == "" {
		policyCfg.StatePath = filepath.Join(t.TempDir(), "tools.json")
	}
	engine, err := New(Options{Policy: policyCfg, ServerName: "test-server"})
	if err != nil {
		t.Fatalf("New error = %v", err)
	}
	return engine
}

func TestEngineZeroConfigIsShadowMode(t *testing.T) {
	eng := newEngine(t, config.Default().Policy)
	if !eng.ShadowMode() {
		t.Error("ShadowMode() = false for the zero-config policy")
	}

	ev := interceptor.ToolCallEvent{
		Direction: interceptor.DirectionRequest,
		Method:    interceptor.MethodToolsCall,
		ToolName:  "delete_everything",
	}
	d := eng.Evaluate(&ev)
	if !d.Allowed {
		t.Errorf("Evaluate() = denied (%s), shadow mode must never block", d.Reason)
	}
	if len(ev.PolicyFlags) != 0 {
		t.Errorf("PolicyFlags = %v, want none for an allowed call", ev.PolicyFlags)
	}
}

func TestEngineDeniedCallIsFlagged(t *testing.T) {
	eng := newEngine(t, config.Policy{
		RBAC: config.RBAC{
			Default: config.DecisionAllow,
			Rules:   []config.Rule{{Client: "*", Deny: []string{"shell_exec"}}},
		},
	})

	ev := interceptor.ToolCallEvent{
		Direction: interceptor.DirectionRequest,
		Method:    interceptor.MethodToolsCall,
		ToolName:  "shell_exec",
		ClientID:  "agent-1",
	}
	d := eng.Evaluate(&ev)

	if d.Allowed {
		t.Fatal("Evaluate() = allowed, want denied")
	}
	if d.Reason == "" {
		t.Error("Decision.Reason is empty; a blocked client needs to be told why")
	}
	if len(ev.PolicyFlags) != 1 || ev.PolicyFlags[0] != FlagRBACDenied {
		t.Errorf("PolicyFlags = %v, want [%s] recorded on the audit event", ev.PolicyFlags, FlagRBACDenied)
	}
}

func TestEngineOnlyJudgesToolCallRequests(t *testing.T) {
	eng := newEngine(t, config.Policy{
		RBAC: config.RBAC{Default: config.DecisionDeny},
	})

	cases := []struct {
		name string
		ev   interceptor.ToolCallEvent
	}{
		{
			"handshake request",
			interceptor.ToolCallEvent{Direction: interceptor.DirectionRequest, Method: "initialize"},
		},
		{
			"tools/list request",
			interceptor.ToolCallEvent{Direction: interceptor.DirectionRequest, Method: interceptor.MethodToolsList},
		},
		{
			"tools/call response",
			interceptor.ToolCallEvent{
				Direction: interceptor.DirectionResponse,
				Method:    interceptor.MethodToolsCall,
				ToolName:  "anything",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := tc.ev
			if d := eng.Evaluate(&ev); !d.Allowed {
				t.Errorf("Evaluate() = denied (%s), want allowed even under default deny", d.Reason)
			}
			if len(ev.PolicyFlags) != 0 {
				t.Errorf("PolicyFlags = %v, want none", ev.PolicyFlags)
			}
		})
	}
}

func TestEngineRejectsInvalidPolicy(t *testing.T) {
	_, err := New(Options{Policy: config.Policy{RBAC: config.RBAC{Default: "nope"}}})
	if err == nil {
		t.Fatal("New() error = nil for an invalid default decision, want an error")
	}
}

func TestEngineReportsWhichDetectorsAreOn(t *testing.T) {
	off := false
	policyCfg := config.Default().Policy
	policyCfg.RugPullDetection = &off

	eng := newEngine(t, policyCfg)
	if eng.StatePath() != "" {
		t.Errorf("StatePath() = %q, want empty when rug-pull detection is off", eng.StatePath())
	}

	eng = newEngine(t, config.Default().Policy)
	if eng.StatePath() == "" {
		t.Error("StatePath() is empty while rug-pull detection is on")
	}
}
