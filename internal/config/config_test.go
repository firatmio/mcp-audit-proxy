package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig drops a config file into a temp dir and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mcp-audit.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("cannot write test config: %v", err)
	}
	return path
}

func TestDefaultIsShadowModeAndValid(t *testing.T) {
	cfg := Default()

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Default() failed its own validation: %v", err)
	}
	if cfg.Policy.RBAC.Default != DecisionAllow {
		t.Errorf("default RBAC decision = %q, want %q", cfg.Policy.RBAC.Default, DecisionAllow)
	}
	if len(cfg.Policy.RBAC.Rules) != 0 {
		t.Errorf("default rules = %v, want none", cfg.Policy.RBAC.Rules)
	}
	if cfg.Sinks.JSONL.Path != DefaultJSONLPath {
		t.Errorf("default jsonl path = %q, want %q", cfg.Sinks.JSONL.Path, DefaultJSONLPath)
	}
	if cfg.Sinks.Webhook.Enabled || cfg.Sinks.Hosted.Enabled {
		t.Error("optional sinks must be off by default; nothing leaves the machine unasked")
	}
	if !cfg.RugPullEnabled() || !cfg.PoisoningEnabled() {
		t.Error("security heuristics must default to on")
	}
}

func TestLoadWithoutConfigFileFallsBackToDefaults(t *testing.T) {
	// An empty search: no env var, and a working directory with no config.
	t.Setenv("MCP_AUDIT_CONFIG", "")
	t.Chdir(t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") error = %v, zero-config must always work", err)
	}
	if cfg.Sinks.JSONL.Path != DefaultJSONLPath {
		t.Errorf("jsonl path = %q, want the default", cfg.Sinks.JSONL.Path)
	}
	if cfg.SourcePath != "" {
		t.Errorf("SourcePath = %q, want empty for built-in defaults", cfg.SourcePath)
	}
}

func TestLoadNamedFileThatDoesNotExistIsAnError(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("Load(missing path) error = nil; an explicitly named config must exist")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want it to say the file was not found", err)
	}
}

func TestLoadPartialConfigKeepsDefaults(t *testing.T) {
	path := writeConfig(t, "mode: stdio\n")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if cfg.Mode != ModeStdio {
		t.Errorf("Mode = %q, want stdio", cfg.Mode)
	}
	if cfg.Sinks.JSONL.Path != DefaultJSONLPath {
		t.Errorf("jsonl path = %q, want the default to survive a partial config", cfg.Sinks.JSONL.Path)
	}
	if cfg.Policy.RBAC.Default != DecisionAllow {
		t.Errorf("rbac default = %q, want allow", cfg.Policy.RBAC.Default)
	}
	if cfg.SourcePath != path {
		t.Errorf("SourcePath = %q, want %q", cfg.SourcePath, path)
	}
}

func TestLoadEmptyFileIsValid(t *testing.T) {
	cfg, err := Load(writeConfig(t, ""))
	if err != nil {
		t.Fatalf("Load(empty file) error = %v", err)
	}
	if cfg.Sinks.JSONL.Path != DefaultJSONLPath {
		t.Errorf("jsonl path = %q, want the default", cfg.Sinks.JSONL.Path)
	}
}

func TestLoadFullConfig(t *testing.T) {
	path := writeConfig(t, `
mode: http

policy:
  rbac:
    default: deny
    rules:
      - client: "ci-*"
        allow: ["read_file"]
        deny: ["shell_exec"]
  rug_pull_detection: false
  poisoning_heuristics: true

sinks:
  jsonl:
    path: "/var/log/mcp/events.jsonl"
  webhook:
    enabled: true
    url: "https://hooks.example.com/mcp"
  hosted:
    enabled: false
    api_key: ""
    endpoint: "https://api.mcp-audit.dev/v1/events"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}

	if cfg.Mode != ModeHTTP {
		t.Errorf("Mode = %q, want http", cfg.Mode)
	}
	if cfg.Policy.RBAC.Default != DecisionDeny {
		t.Errorf("rbac default = %q, want deny", cfg.Policy.RBAC.Default)
	}
	if len(cfg.Policy.RBAC.Rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(cfg.Policy.RBAC.Rules))
	}
	rule := cfg.Policy.RBAC.Rules[0]
	if rule.Client != "ci-*" || len(rule.Allow) != 1 || len(rule.Deny) != 1 {
		t.Errorf("rule = %+v, want client ci-* with one allow and one deny", rule)
	}
	if cfg.RugPullEnabled() {
		t.Error("RugPullEnabled() = true, the file set it to false")
	}
	if !cfg.PoisoningEnabled() {
		t.Error("PoisoningEnabled() = false, the file set it to true")
	}
	if cfg.Sinks.JSONL.Path != "/var/log/mcp/events.jsonl" {
		t.Errorf("jsonl path = %q", cfg.Sinks.JSONL.Path)
	}
	if !cfg.Sinks.Webhook.Enabled || cfg.Sinks.Webhook.URL == "" {
		t.Errorf("webhook = %+v, want enabled with a URL", cfg.Sinks.Webhook)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	// A typo in a security config must be loud, not silently ignored.
	_, err := Load(writeConfig(t, "policy:\n  rbak:\n    default: deny\n"))
	if err == nil {
		t.Fatal("Load(config with a typo) error = nil, want an error")
	}
	if !strings.Contains(err.Error(), "rbak") {
		t.Errorf("error = %q, want it to name the unknown key", err)
	}
}

func TestLoadRejectsMalformedYAML(t *testing.T) {
	_, err := Load(writeConfig(t, "policy:\n\t- broken: [unclosed\n"))
	if err == nil {
		t.Fatal("Load(malformed yaml) error = nil, want an error")
	}
	if !strings.Contains(err.Error(), "cannot parse") {
		t.Errorf("error = %q, want a plain-English parse error", err)
	}
}

func TestValidateCatchesConfigMistakes(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantMsg string
	}{
		{
			"unknown mode",
			func(c *Config) { c.Mode = "grpc" },
			"mode must be",
		},
		{
			"unknown rbac default",
			func(c *Config) { c.Policy.RBAC.Default = "maybe" },
			"policy.rbac.default",
		},
		{
			"rule without a client",
			func(c *Config) { c.Policy.RBAC.Rules = []Rule{{Deny: []string{"x"}}} },
			"client is required",
		},
		{
			"rule with neither allow nor deny",
			func(c *Config) { c.Policy.RBAC.Rules = []Rule{{Client: "*"}} },
			"neither allow nor deny",
		},
		{
			"empty jsonl path",
			func(c *Config) { c.Sinks.JSONL.Path = "" },
			"sinks.jsonl.path",
		},
		{
			"webhook enabled without url",
			func(c *Config) { c.Sinks.Webhook = WebhookSink{Enabled: true} },
			"sinks.webhook.url",
		},
		{
			"hosted enabled without api key",
			func(c *Config) { c.Sinks.Hosted = HostedSink{Enabled: true, Endpoint: "https://x"} },
			"api_key",
		},
		{
			"webhook url without a scheme",
			func(c *Config) { c.Sinks.Webhook = WebhookSink{Enabled: true, URL: "hooks.slack.com/x"} },
			"http://",
		},
		{
			"unknown webhook format",
			func(c *Config) {
				c.Sinks.Webhook = WebhookSink{Enabled: true, URL: "https://x", Format: "carrier-pigeon"}
			},
			"sinks.webhook.format",
		},
		{
			"unknown webhook send selector",
			func(c *Config) {
				c.Sinks.Webhook = WebhookSink{Enabled: true, URL: "https://x", Send: "sometimes"}
			},
			"sinks.webhook.send",
		},
		{
			"rug-pull detection with nowhere to remember",
			func(c *Config) { c.Policy.StatePath = "" },
			"policy.state_path",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() error = nil, want an error mentioning %q", tc.wantMsg)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("Validate() error = %q, want it to mention %q", err, tc.wantMsg)
			}
		})
	}
}

func TestValidWebhookConfigurationsPass(t *testing.T) {
	cases := []WebhookSink{
		{Enabled: true, URL: "https://hooks.slack.com/services/x"},
		{Enabled: true, URL: "http://siem.internal/ingest", Format: FormatGeneric, Send: SendAll},
		{Enabled: true, URL: "https://discord.com/api/webhooks/1/2", Format: FormatAuto, Send: SendFlagged},
		{Enabled: false}, // a disabled webhook needs no URL
	}

	for _, webhook := range cases {
		cfg := Default()
		cfg.Sinks.Webhook = webhook
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() error = %v for %+v, want nil", err, webhook)
		}
	}
}

func TestStatePathIsOptionalWhenRugPullIsOff(t *testing.T) {
	off := false
	cfg := Default()
	cfg.Policy.RugPullDetection = &off
	cfg.Policy.StatePath = ""

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() error = %v; state_path only matters when the detector runs", err)
	}
}

func TestLoadFillsInTheStatePath(t *testing.T) {
	cfg, err := Load(writeConfig(t, "policy:\n  rug_pull_detection: true\n"))
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if cfg.Policy.StatePath != DefaultStatePath {
		t.Errorf("state_path = %q, want the default %q", cfg.Policy.StatePath, DefaultStatePath)
	}
}

func TestLoadWebhookOptions(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
sinks:
  webhook:
    enabled: true
    url: "https://example.com/hook"
    format: discord
    send: flagged
`))
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if got := cfg.Sinks.Webhook.ResolvedFormat(); got != FormatDiscord {
		t.Errorf("ResolvedFormat() = %q, want discord", got)
	}
	if got := cfg.Sinks.Webhook.ResolvedSend(); got != SendFlagged {
		t.Errorf("ResolvedSend() = %q, want flagged", got)
	}
}

func TestExpandPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory in this environment")
	}

	got, err := ExpandPath("~/.mcp-audit/logs/events.jsonl")
	if err != nil {
		t.Fatalf("ExpandPath error = %v", err)
	}
	want := filepath.Join(home, ".mcp-audit", "logs", "events.jsonl")
	if got != want {
		t.Errorf("ExpandPath(~/...) = %q, want %q", got, want)
	}

	if _, err := ExpandPath(""); err == nil {
		t.Error("ExpandPath(\"\") error = nil, want an error")
	}

	abs, err := ExpandPath("relative/path.jsonl")
	if err != nil {
		t.Fatalf("ExpandPath(relative) error = %v", err)
	}
	if !filepath.IsAbs(abs) {
		t.Errorf("ExpandPath(relative) = %q, want an absolute path", abs)
	}
}

func TestSearchPathsHonoursEnvVar(t *testing.T) {
	t.Setenv("MCP_AUDIT_CONFIG", "/custom/place.yaml")

	paths := SearchPaths()
	if len(paths) == 0 || paths[0] != "/custom/place.yaml" {
		t.Errorf("SearchPaths() = %v, want MCP_AUDIT_CONFIG first", paths)
	}
}

func TestLoadFindsConfigInWorkingDirectory(t *testing.T) {
	t.Setenv("MCP_AUDIT_CONFIG", "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mcp-audit.yaml"), []byte("mode: http\n"), 0o600); err != nil {
		t.Fatalf("cannot write config: %v", err)
	}
	t.Chdir(dir)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") error = %v", err)
	}
	if cfg.Mode != ModeHTTP {
		t.Errorf("Mode = %q, want the config found in the working directory to apply", cfg.Mode)
	}
}
