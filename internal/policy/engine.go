// Package policy evaluates every intercepted MCP message against the
// configured security rules.
//
// The engine is deliberately cheap: it runs inline on the proxy's hot path,
// before a message is forwarded, so that a denied call can be stopped rather
// than merely reported. Anything expensive belongs in a sink, not here.
package policy

import (
	"io"
	"log"

	"github.com/firatmio/mcp-audit-proxy/internal/config"
	"github.com/firatmio/mcp-audit-proxy/internal/interceptor"
	"github.com/firatmio/mcp-audit-proxy/pkg/event"
)

// Policy flags attached to ToolCallEvent.PolicyFlags.
//
// The values live in pkg/event alongside the record itself: they are part of
// the wire format, and a consumer filtering on "rug_pull" needs the same
// spelling we write.
const (
	FlagRBACDenied       = event.FlagRBACDenied
	FlagRugPull          = event.FlagRugPull
	FlagPoisoningSuspect = event.FlagPoisoningSuspect
)

// Decision is the outcome of evaluating one event.
type Decision struct {
	// Allowed reports whether the message may be forwarded. Only tools/call
	// requests are ever refused; everything else always passes.
	Allowed bool
	// Reason explains the decision in plain English, for CLI output and for
	// the JSON-RPC error returned to a blocked client.
	Reason string
	// Flags are the policy flags recorded on the audit event.
	Flags []string
}

// Options configures an Engine.
type Options struct {
	// Policy is the policy section of the config.
	Policy config.Policy
	// ServerName scopes the rug-pull fingerprints, so two MCP servers that
	// both advertise a "read_file" tool do not shadow each other.
	ServerName string
	// Logger receives the alarms. Detection warnings go to the operator's
	// terminal as well as to the audit log. Nil discards them.
	Logger *log.Logger
}

// Engine orchestrates the individual policy checks. It is safe for concurrent
// use.
type Engine struct {
	rbac      *RBAC
	rugPull   *RugPullDetector
	poisoning *PoisoningScanner
	logger    *log.Logger
}

// New builds an Engine from opts, loading any persistent state the enabled
// checks need.
func New(opts Options) (*Engine, error) {
	rbac, err := NewRBAC(opts.Policy.RBAC)
	if err != nil {
		return nil, err
	}

	logger := opts.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	e := &Engine{rbac: rbac, logger: logger}

	if opts.Policy.RugPullEnabled() {
		statePath := opts.Policy.StatePath
		if statePath == "" {
			statePath = config.DefaultStatePath
		}
		detector, err := NewRugPullDetector(statePath, opts.ServerName)
		if err != nil {
			return nil, err
		}
		e.rugPull = detector
	}

	if opts.Policy.PoisoningEnabled() {
		e.poisoning = NewPoisoningScanner()
	}

	return e, nil
}

// ShadowMode reports whether the engine can only observe, never block. This is
// the zero-config default and the CLI announces it at startup.
//
// The rug-pull and poisoning checks never block anything, so they do not
// change the answer: they raise alarms and record flags.
func (e *Engine) ShadowMode() bool {
	return e.rbac.ShadowMode()
}

// StatePath returns where tool fingerprints are stored, or "" when rug-pull
// detection is off.
func (e *Engine) StatePath() string {
	if e.rugPull == nil {
		return ""
	}
	return e.rugPull.Path()
}

// Evaluate applies every enabled check to ev, records any resulting flags on
// the event itself, and returns the decision.
//
// Responses are never blocked — by the time a result comes back the side
// effect has already happened, so refusing it would only hide evidence.
func (e *Engine) Evaluate(ev *interceptor.ToolCallEvent) Decision {
	switch {
	case ev.Direction == interceptor.DirectionResponse && ev.Method == interceptor.MethodToolsList:
		return e.inspectToolList(ev)
	case ev.Direction == interceptor.DirectionRequest && ev.IsToolCall():
		return e.checkRBAC(ev)
	default:
		return Decision{Allowed: true}
	}
}

// checkRBAC runs the allow/deny rules against a tool call.
func (e *Engine) checkRBAC(ev *interceptor.ToolCallEvent) Decision {
	allowed, reason := e.rbac.Check(ev.ClientID, ev.ToolName)
	if allowed {
		return Decision{Allowed: true, Reason: reason}
	}

	ev.AddFlag(FlagRBACDenied)
	return Decision{Allowed: false, Reason: reason, Flags: []string{FlagRBACDenied}}
}

// inspectToolList runs the checks that read tool advertisements: rug-pull
// detection and the poisoning heuristics.
//
// A tools/list result is never blocked. Refusing it would break the session
// outright, and the operator needs to see the evidence — which is in this very
// event's result payload.
func (e *Engine) inspectToolList(ev *interceptor.ToolCallEvent) Decision {
	if e.rugPull == nil && e.poisoning == nil {
		return Decision{Allowed: true}
	}

	tools, err := ParseToolList(ev.Result)
	if err != nil {
		e.logger.Printf("could not inspect a tools/list result: %v", err)
		return Decision{Allowed: true}
	}
	if len(tools) == 0 {
		return Decision{Allowed: true}
	}

	decision := Decision{Allowed: true}

	if e.rugPull != nil {
		changes, err := e.rugPull.Inspect(tools)
		if err != nil {
			// A store we could not update is worth saying out loud, because
			// the next run will not remember what we just saw.
			e.logger.Printf("rug-pull detection: %v", err)
		}
		for _, change := range changes {
			e.logger.Printf("ALERT rug pull on server %q: %s", ev.ServerName, change)
		}
		if len(changes) > 0 {
			ev.AddFlag(FlagRugPull)
			decision.Flags = append(decision.Flags, FlagRugPull)
			decision.Reason = changes[0].String()
		}
	}

	if e.poisoning != nil {
		findings := e.poisoning.Scan(tools)
		for _, finding := range findings {
			e.logger.Printf("ALERT possible tool poisoning on server %q: %s", ev.ServerName, finding)
		}
		if len(findings) > 0 {
			ev.AddFlag(FlagPoisoningSuspect)
			decision.Flags = append(decision.Flags, FlagPoisoningSuspect)
			if decision.Reason == "" {
				decision.Reason = findings[0].String()
			}
		}
	}

	return decision
}
