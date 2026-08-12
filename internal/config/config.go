// Package config loads and validates mcp-audit's config.yaml.
//
// The guiding rule is zero-config: a missing config file is not an error. Load
// falls back to defaults that log everything and block nothing (shadow mode),
// so `mcp-audit run -- <cmd>` works on a machine that has never seen a config
// file.
package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Proxy modes accepted by the `mode` key.
const (
	ModeStdio = "stdio"
	ModeHTTP  = "http"
)

// RBAC default decisions accepted by `policy.rbac.default`.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

// DefaultJSONLPath is where the always-on local audit log lives when the user
// has not said otherwise.
const DefaultJSONLPath = "~/.mcp-audit/logs/events.jsonl"

// DefaultHostedEndpoint is the Team-tier ingest URL.
const DefaultHostedEndpoint = "https://api.mcp-audit.dev/v1/events"

// DefaultStatePath is where rug-pull detection remembers what each tool looked
// like the first time it was advertised. It has to outlive the process: a rug
// pull is a change made days after the user approved the tool.
const DefaultStatePath = "~/.mcp-audit/state/tools.json"

// Config is the whole of config.yaml.
type Config struct {
	Mode   string `yaml:"mode"`
	Policy Policy `yaml:"policy"`
	Sinks  Sinks  `yaml:"sinks"`

	// SourcePath records where this config came from, or "" for built-in
	// defaults. Used only for user-facing messages.
	SourcePath string `yaml:"-"`
}

// Policy holds the security-engine settings.
type Policy struct {
	RBAC RBAC `yaml:"rbac"`
	// RugPullDetection and PoisoningHeuristics are pointers so that "absent"
	// is distinguishable from "explicitly false" and defaults can apply.
	RugPullDetection    *bool `yaml:"rug_pull_detection"`
	PoisoningHeuristics *bool `yaml:"poisoning_heuristics"`
	// StatePath is where tool fingerprints are remembered between runs.
	StatePath string `yaml:"state_path"`
}

// RugPullEnabled reports whether rug-pull detection should run. Absent means on.
func (p *Policy) RugPullEnabled() bool {
	return p.RugPullDetection == nil || *p.RugPullDetection
}

// PoisoningEnabled reports whether tool-poisoning heuristics should run.
// Absent means on.
func (p *Policy) PoisoningEnabled() bool {
	return p.PoisoningHeuristics == nil || *p.PoisoningHeuristics
}

// RBAC is the allow/deny configuration for tool calls.
type RBAC struct {
	// Default is the decision when no rule matches: "allow" (shadow mode,
	// the out-of-the-box behaviour) or "deny".
	Default string `yaml:"default"`
	Rules   []Rule `yaml:"rules"`
}

// Rule is one allow/deny entry. Client and the tool patterns support "*" as a
// wildcard matching any run of characters.
type Rule struct {
	Client string   `yaml:"client"`
	Allow  []string `yaml:"allow"`
	Deny   []string `yaml:"deny"`
}

// Sinks configures where audit events are written.
type Sinks struct {
	JSONL   JSONLSink   `yaml:"jsonl"`
	Webhook WebhookSink `yaml:"webhook"`
	Hosted  HostedSink  `yaml:"hosted"`
}

// JSONLSink is the local newline-delimited JSON log. It is always enabled.
type JSONLSink struct {
	Path string `yaml:"path"`
}

// Webhook payload formats accepted by `sinks.webhook.format`.
const (
	// FormatAuto picks a format from the URL: Slack and Discord webhook hosts
	// are recognised, anything else is treated as generic.
	FormatAuto = "auto"
	// FormatGeneric posts the audit event itself as JSON, for a SIEM.
	FormatGeneric = "generic"
	// FormatSlack posts a Slack-compatible {"text": ...} message.
	FormatSlack = "slack"
	// FormatDiscord posts a Discord-compatible {"content": ...} message.
	FormatDiscord = "discord"
)

// Webhook delivery selectors accepted by `sinks.webhook.send`.
const (
	// SendAll ships every audit event.
	SendAll = "all"
	// SendFlagged ships only events the policy engine flagged.
	SendFlagged = "flagged"
)

// WebhookSink is the optional generic/SIEM HTTP export.
type WebhookSink struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
	// Format selects the payload shape. Empty means "auto".
	Format string `yaml:"format"`
	// Send selects which events are shipped. Empty means "all" for the
	// generic format and "flagged" for the chat formats — nobody wants every
	// ping notification in a Slack channel.
	Send string `yaml:"send"`
}

// ResolvedFormat returns the payload format to use, resolving "auto" against
// the webhook URL.
func (w *WebhookSink) ResolvedFormat() string {
	format := strings.ToLower(strings.TrimSpace(w.Format))
	if format != "" && format != FormatAuto {
		return format
	}

	host := strings.ToLower(w.URL)
	switch {
	case strings.Contains(host, "hooks.slack.com"):
		return FormatSlack
	case strings.Contains(host, "discord.com/api/webhooks"),
		strings.Contains(host, "discordapp.com/api/webhooks"):
		return FormatDiscord
	default:
		return FormatGeneric
	}
}

// ResolvedSend returns which events to ship, applying the per-format default.
func (w *WebhookSink) ResolvedSend() string {
	send := strings.ToLower(strings.TrimSpace(w.Send))
	if send != "" {
		return send
	}
	if w.ResolvedFormat() == FormatGeneric {
		return SendAll
	}
	return SendFlagged
}

// HostedSink is the optional Team-tier backend export. Week 4+.
type HostedSink struct {
	Enabled  bool   `yaml:"enabled"`
	APIKey   string `yaml:"api_key"`
	Endpoint string `yaml:"endpoint"`
}

// Default returns the zero-config configuration: log everything locally, block
// nothing, ship nothing off the machine.
func Default() Config {
	rugPull, poisoning := true, true
	return Config{
		Policy: Policy{
			RBAC: RBAC{
				Default: DecisionAllow,
			},
			RugPullDetection:    &rugPull,
			PoisoningHeuristics: &poisoning,
			StatePath:           DefaultStatePath,
		},
		Sinks: Sinks{
			JSONL:  JSONLSink{Path: DefaultJSONLPath},
			Hosted: HostedSink{Endpoint: DefaultHostedEndpoint},
		},
	}
}

// RugPullEnabled reports whether rug-pull detection should run.
func (c *Config) RugPullEnabled() bool { return c.Policy.RugPullEnabled() }

// PoisoningEnabled reports whether tool-poisoning heuristics should run.
func (c *Config) PoisoningEnabled() bool { return c.Policy.PoisoningEnabled() }

// Load reads configuration for the given path.
//
// If path is empty, Load looks in the standard locations (see SearchPaths) and
// silently falls back to Default when none exist. If path is non-empty, a
// missing or unreadable file is a hard error — the user asked for that file by
// name and deserves to know it is not there.
func Load(path string) (Config, error) {
	if path != "" {
		cfg, err := loadFile(path)
		if err != nil {
			return Config{}, err
		}
		return cfg, nil
	}

	for _, candidate := range SearchPaths() {
		if candidate == "" {
			continue
		}
		if _, err := os.Stat(candidate); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			continue
		}
		return loadFile(candidate)
	}

	cfg := Default()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// SearchPaths lists, in order of precedence, where Load looks for a config
// file when none was given on the command line.
func SearchPaths() []string {
	paths := []string{}
	if fromEnv := os.Getenv("MCP_AUDIT_CONFIG"); fromEnv != "" {
		paths = append(paths, fromEnv)
	}
	paths = append(paths, "mcp-audit.yaml", "mcp-audit.yml")
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".mcp-audit", "config.yaml"))
	}
	return paths
}

// loadFile parses one config file on top of the defaults.
func loadFile(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Config{}, fmt.Errorf("config file not found: %s", path)
		}
		return Config{}, fmt.Errorf("cannot read config file %s: %w", path, err)
	}
	defer f.Close()

	cfg := Default()
	dec := yaml.NewDecoder(f)
	// Reject unknown keys: a typo in a security config should be loud, not
	// silently ignored.
	dec.KnownFields(true)
	// An empty file decodes to io.EOF, which just means "use every default".
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("cannot parse config file %s: %w", path, err)
	}

	cfg.SourcePath = path
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid config file %s: %w", path, err)
	}
	return cfg, nil
}

// applyDefaults fills in keys the file left empty.
func (c *Config) applyDefaults() {
	d := Default()
	if c.Policy.RBAC.Default == "" {
		c.Policy.RBAC.Default = d.Policy.RBAC.Default
	}
	if c.Policy.StatePath == "" {
		c.Policy.StatePath = d.Policy.StatePath
	}
	if c.Sinks.JSONL.Path == "" {
		c.Sinks.JSONL.Path = d.Sinks.JSONL.Path
	}
	if c.Sinks.Hosted.Endpoint == "" {
		c.Sinks.Hosted.Endpoint = d.Sinks.Hosted.Endpoint
	}
}

// Validate checks the config for mistakes that would otherwise surface as
// confusing runtime behaviour. Messages are written for a CLI user, not a
// stack trace reader.
func (c *Config) Validate() error {
	switch c.Mode {
	case "", ModeStdio, ModeHTTP:
	default:
		return fmt.Errorf("mode must be %q or %q, got %q", ModeStdio, ModeHTTP, c.Mode)
	}

	switch strings.ToLower(c.Policy.RBAC.Default) {
	case DecisionAllow, DecisionDeny:
	default:
		return fmt.Errorf("policy.rbac.default must be %q or %q, got %q",
			DecisionAllow, DecisionDeny, c.Policy.RBAC.Default)
	}

	for i, rule := range c.Policy.RBAC.Rules {
		if rule.Client == "" {
			return fmt.Errorf("policy.rbac.rules[%d]: client is required (use \"*\" to match every client)", i)
		}
		if len(rule.Allow) == 0 && len(rule.Deny) == 0 {
			return fmt.Errorf("policy.rbac.rules[%d]: rule for client %q has neither allow nor deny entries", i, rule.Client)
		}
	}

	if c.Policy.RugPullEnabled() && c.Policy.StatePath == "" {
		return errors.New("policy.state_path cannot be empty while policy.rug_pull_detection is on")
	}
	if c.Sinks.JSONL.Path == "" {
		return errors.New("sinks.jsonl.path cannot be empty; the local audit log is always enabled")
	}
	if c.Sinks.Webhook.Enabled {
		if c.Sinks.Webhook.URL == "" {
			return errors.New("sinks.webhook.enabled is true but sinks.webhook.url is empty")
		}
		if !strings.HasPrefix(c.Sinks.Webhook.URL, "http://") && !strings.HasPrefix(c.Sinks.Webhook.URL, "https://") {
			return fmt.Errorf("sinks.webhook.url must start with http:// or https://, got %q", c.Sinks.Webhook.URL)
		}
		switch strings.ToLower(strings.TrimSpace(c.Sinks.Webhook.Format)) {
		case "", FormatAuto, FormatGeneric, FormatSlack, FormatDiscord:
		default:
			return fmt.Errorf("sinks.webhook.format must be one of %q, %q, %q or %q, got %q",
				FormatAuto, FormatGeneric, FormatSlack, FormatDiscord, c.Sinks.Webhook.Format)
		}
		switch strings.ToLower(strings.TrimSpace(c.Sinks.Webhook.Send)) {
		case "", SendAll, SendFlagged:
		default:
			return fmt.Errorf("sinks.webhook.send must be %q or %q, got %q",
				SendAll, SendFlagged, c.Sinks.Webhook.Send)
		}
	}
	if c.Sinks.Hosted.Enabled {
		if c.Sinks.Hosted.APIKey == "" {
			return errors.New("sinks.hosted.enabled is true but sinks.hosted.api_key is empty")
		}
		if c.Sinks.Hosted.Endpoint == "" {
			return errors.New("sinks.hosted.enabled is true but sinks.hosted.endpoint is empty")
		}
	}
	return nil
}

// ExpandPath resolves a leading "~" against the current user's home directory
// and returns an absolute path. Config files are written by humans, and humans
// write "~/.mcp-audit/logs/events.jsonl".
func ExpandPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("path is empty")
	}
	if path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot resolve %q: home directory is unknown: %w", path, err)
		}
		if path == "~" {
			return home, nil
		}
		path = filepath.Join(home, path[2:])
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("cannot resolve %q: %w", path, err)
	}
	return abs, nil
}
