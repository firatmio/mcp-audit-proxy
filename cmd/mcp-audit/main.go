// Command mcp-audit is a transparent auditing proxy for MCP servers.
//
//	mcp-audit run -- npx -y @modelcontextprotocol/server-filesystem /tmp
//	mcp-audit serve --target https://example.com/mcp --listen :9000
//
// Every JSON-RPC message that crosses the proxy is recorded to a local JSONL
// audit log. With no config file it observes and never blocks.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/firatmio/mcp-audit-proxy/internal/config"
	"github.com/firatmio/mcp-audit-proxy/internal/httpproxy"
	"github.com/firatmio/mcp-audit-proxy/internal/interceptor"
	"github.com/firatmio/mcp-audit-proxy/internal/policy"
	"github.com/firatmio/mcp-audit-proxy/internal/sinks"
	"github.com/firatmio/mcp-audit-proxy/internal/stdio"
)

// Version is stamped at build time with -ldflags "-X main.Version=v0.1.0".
var Version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

// run executes a subcommand and returns the process exit code. Diagnostics go
// to stderr because in stdio mode stdout belongs to the MCP protocol.
func run(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}

	switch args[0] {
	case "run":
		return dispatch(cmdRun(args[1:]))
	case "serve":
		return dispatch(cmdServe(args[1:]))
	case "version", "--version", "-v":
		fmt.Printf("mcp-audit %s\n", Version)
		return 0
	case "help", "--help", "-h":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "mcp-audit: unknown command %q\n\n", args[0])
		usage(os.Stderr)
		return 2
	}
}

// dispatch turns a subcommand result into an exit code, reporting any error in
// plain English.
func dispatch(code int, err error) int {
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-audit: %v\n", err)
		if code == 0 {
			return 1
		}
	}
	return code
}

func usage(w *os.File) {
	fmt.Fprintf(w, `mcp-audit %s — a transparent audit proxy for MCP servers

Usage:
  mcp-audit run [flags] -- <command> [args...]   wrap a local (stdio) MCP server
  mcp-audit serve --target <url> [flags]         proxy a remote (HTTP) MCP server
  mcp-audit version                              print the version

Common flags:
  --config <path>       config file to use (default: search, then built-in defaults)
  --log <path>          audit log path, overriding the config
  --server-name <name>  name recorded in every audit event
  --client-id <id>      client identity recorded in every audit event
  --quiet               suppress the startup banner

Flags for serve:
  --target <url>        upstream MCP server URL (required)
  --listen <addr>       address to listen on (default ":9000")

Examples:
  mcp-audit run -- npx -y @modelcontextprotocol/server-filesystem /tmp
  mcp-audit serve --target https://example.com/mcp --listen :9000

With no config file mcp-audit runs in shadow mode: it records everything and
blocks nothing. Audit events are written to %s
`, Version, config.DefaultJSONLPath)
}

// commonFlags are the flags every subcommand accepts.
type commonFlags struct {
	configPath string
	logPath    string
	serverName string
	clientID   string
	quiet      bool
}

func (c *commonFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.configPath, "config", "", "path to config.yaml")
	fs.StringVar(&c.logPath, "log", "", "audit log path, overriding the config")
	fs.StringVar(&c.serverName, "server-name", "", "name recorded in every audit event")
	fs.StringVar(&c.clientID, "client-id", "", "client identity recorded in every audit event")
	fs.BoolVar(&c.quiet, "quiet", false, "suppress the startup banner")
}

// cmdRun implements `mcp-audit run -- <command> [args...]`.
func cmdRun(args []string) (int, error) {
	proxyArgs, serverCmd := splitAtDoubleDash(args)

	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var common commonFlags
	common.register(fs)
	if err := fs.Parse(proxyArgs); err != nil {
		return 2, nil // flag package already printed the problem
	}

	// Tolerate `mcp-audit run npx ...` without the separator.
	if len(serverCmd) == 0 {
		serverCmd = fs.Args()
	}
	if len(serverCmd) == 0 {
		return 2, fmt.Errorf("no MCP server command given\n\nusage: mcp-audit run -- <command> [args...]")
	}

	cfg, err := loadConfig(common)
	if err != nil {
		return 1, err
	}

	serverName := common.serverName
	if serverName == "" {
		serverName = strings.TrimSuffix(filepath.Base(serverCmd[0]), filepath.Ext(serverCmd[0]))
	}

	logger := log.New(os.Stderr, "mcp-audit: ", 0)
	pipeline, err := newPipeline(cfg, serverName, common.clientID, logger)
	if err != nil {
		return 1, err
	}
	defer pipeline.close(logger, common.quiet)

	if !common.quiet {
		banner(cfg, pipeline, fmt.Sprintf("stdio, wrapping %q", strings.Join(serverCmd, " ")))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	wrapper := &stdio.Wrapper{
		Command:     serverCmd[0],
		Args:        serverCmd[1:],
		Interceptor: pipeline.interceptor,
		Policy:      pipeline.policy,
		Dispatcher:  pipeline.dispatcher,
		Logger:      logger,
	}
	return wrapper.Run(ctx)
}

// cmdServe implements `mcp-audit serve --target <url>`.
func cmdServe(args []string) (int, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var common commonFlags
	common.register(fs)
	target := fs.String("target", "", "upstream MCP server URL (required)")
	listen := fs.String("listen", ":9000", "address to listen on")
	if err := fs.Parse(args); err != nil {
		return 2, nil
	}

	if *target == "" {
		return 2, fmt.Errorf("--target is required\n\nusage: mcp-audit serve --target <url> [--listen :9000]")
	}

	cfg, err := loadConfig(common)
	if err != nil {
		return 1, err
	}

	serverName := common.serverName
	if serverName == "" {
		serverName = *target
	}

	logger := log.New(os.Stderr, "mcp-audit: ", 0)
	pipeline, err := newPipeline(cfg, serverName, common.clientID, logger)
	if err != nil {
		return 1, err
	}
	defer pipeline.close(logger, common.quiet)

	proxy, err := httpproxy.New(httpproxy.Config{
		Target:      *target,
		Interceptor: pipeline.interceptor,
		Policy:      pipeline.policy,
		Dispatcher:  pipeline.dispatcher,
		Logger:      logger,
	})
	if err != nil {
		return 1, err
	}

	if !common.quiet {
		banner(cfg, pipeline, fmt.Sprintf("http, %s -> %s", *listen, proxy.Target()))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := proxy.ListenAndServe(ctx, *listen); err != nil {
		return 1, err
	}
	return 0, nil
}

// pipeline bundles the audit components shared by both modes.
type pipeline struct {
	interceptor *interceptor.Interceptor
	policy      *policy.Engine
	dispatcher  *sinks.Dispatcher
	jsonl       *sinks.JSONL
	webhook     *sinks.Webhook
	hosted      *sinks.Hosted
}

// newPipeline wires the interceptor, policy engine and sinks together.
func newPipeline(cfg config.Config, serverName, clientID string, logger *log.Logger) (*pipeline, error) {
	engine, err := policy.New(policy.Options{
		Policy:     cfg.Policy,
		ServerName: serverName,
		Logger:     logger,
	})
	if err != nil {
		return nil, err
	}

	jsonl, err := sinks.NewJSONL(cfg.Sinks.JSONL.Path)
	if err != nil {
		return nil, err
	}

	dispatcher := sinks.NewDispatcher(logger)
	// The local log is required: it applies backpressure rather than dropping
	// events. Optional sinks are best-effort and drop instead.
	dispatcher.Add(jsonl, true)

	var webhook *sinks.Webhook
	if cfg.Sinks.Webhook.Enabled {
		webhook, err = sinks.NewWebhook(cfg.Sinks.Webhook)
		if err != nil {
			return nil, err
		}
		dispatcher.Add(webhook, false)
	}

	var hosted *sinks.Hosted
	if cfg.Sinks.Hosted.Enabled {
		hosted, err = sinks.NewHosted(cfg.Sinks.Hosted)
		if err != nil {
			return nil, err
		}
		dispatcher.Add(hosted, false)
	}

	return &pipeline{
		interceptor: interceptor.New(interceptor.Options{
			ServerName: serverName,
			ClientID:   clientID,
		}),
		policy:     engine,
		dispatcher: dispatcher,
		jsonl:      jsonl,
		webhook:    webhook,
		hosted:     hosted,
	}, nil
}

// close drains the sinks and reports anything that went wrong.
func (p *pipeline) close(logger *log.Logger, quiet bool) {
	if err := p.dispatcher.Close(); err != nil {
		logger.Printf("%v", err)
	}
	if quiet {
		return
	}
	for name, stat := range p.dispatcher.Stats() {
		if stat.Dropped > 0 || stat.Failed > 0 {
			logger.Printf("sink %s: %d event(s) dropped, %d write failure(s)", name, stat.Dropped, stat.Failed)
		}
	}
}

// banner prints the one-time startup summary to stderr.
func banner(cfg config.Config, p *pipeline, mode string) {
	source := cfg.SourcePath
	if source == "" {
		source = "built-in defaults (no config file found)"
	}
	policyMode := "enforcing"
	if p.policy.ShadowMode() {
		policyMode = "shadow (recording only, nothing is blocked)"
	}
	var detectors []string
	if cfg.RugPullEnabled() {
		detectors = append(detectors, "rug-pull")
	}
	if cfg.PoisoningEnabled() {
		detectors = append(detectors, "tool-poisoning")
	}
	if len(detectors) == 0 {
		detectors = append(detectors, "none")
	}

	fmt.Fprintf(os.Stderr, "mcp-audit %s | mode: %s\nmcp-audit config: %s\nmcp-audit policy: %s\nmcp-audit detectors: %s\nmcp-audit audit log: %s\n",
		Version, mode, source, policyMode, strings.Join(detectors, ", "), p.jsonl.Path())
	if path := p.policy.StatePath(); path != "" {
		fmt.Fprintf(os.Stderr, "mcp-audit tool fingerprints: %s\n", path)
	}
	if p.webhook != nil {
		fmt.Fprintf(os.Stderr, "mcp-audit webhook: %s format, sending %s events\n",
			p.webhook.Format(), p.webhook.Send())
	}
}

// loadConfig reads the config file and applies the command-line overrides.
func loadConfig(common commonFlags) (config.Config, error) {
	cfg, err := config.Load(common.configPath)
	if err != nil {
		return config.Config{}, err
	}
	if common.logPath != "" {
		cfg.Sinks.JSONL.Path = common.logPath
	}
	return cfg, nil
}

// splitAtDoubleDash splits args at the first "--", returning the flags meant
// for mcp-audit and the command line meant for the MCP server.
func splitAtDoubleDash(args []string) (before, after []string) {
	for i, arg := range args {
		if arg == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}
