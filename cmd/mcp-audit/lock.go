package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/firatmio/mcp-audit-proxy/internal/config"
	"github.com/firatmio/mcp-audit-proxy/internal/policy"
)

// cmdLock implements `mcp-audit lock <status|diff|approve>`.
//
// The proxy records what every tool looked like when it was first seen and keeps
// raising the alarm if that changes. This command is where a person looks at the
// change and decides: nothing is accepted unless it is approved here.
func cmdLock(args []string) (int, error) {
	if len(args) == 0 {
		lockUsage(os.Stderr)
		return 2, nil
	}
	sub, rest := args[0], args[1:]

	switch sub {
	case "status":
		return lockStatus(rest, os.Stdout)
	case "diff":
		return lockDiff(rest, os.Stdout)
	case "approve":
		return lockApprove(rest, os.Stdout)
	case "help", "--help", "-h":
		lockUsage(os.Stdout)
		return 0, nil
	default:
		fmt.Fprintf(os.Stderr, "mcp-audit lock: unknown subcommand %q\n\n", sub)
		lockUsage(os.Stderr)
		return 2, nil
	}
}

func lockUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  mcp-audit lock status                    list tools that changed since approval
  mcp-audit lock diff [server [tool]]      show what changed
  mcp-audit lock approve --all             accept every pending change
  mcp-audit lock approve <server> [tool]   accept one server's (or one tool's) changes

Flags:
  --state <path>    tool fingerprint store (default: from the config, else the built-in path)
  --config <path>   config file to read the store path from
`)
}

// lockFlags are the flags every lock subcommand accepts.
type lockFlags struct {
	state  string
	config string
}

func (l *lockFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&l.state, "state", "", "tool fingerprint store")
	fs.StringVar(&l.config, "config", "", "path to config.yaml")
}

// open resolves the store path: --state wins, then the config, then the default.
func (l *lockFlags) open() (*policy.LockStore, error) {
	path := l.state
	if path == "" {
		cfg, err := config.Load(l.config)
		if err != nil {
			return nil, err
		}
		path = cfg.Policy.StatePath
	}
	if path == "" {
		path = config.DefaultStatePath
	}
	return policy.OpenLockStore(path)
}

func lockStatus(args []string, out io.Writer) (int, error) {
	fs := flag.NewFlagSet("lock status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var flags lockFlags
	flags.register(fs)
	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return 2, nil
	}
	if len(rest) > 0 {
		return 2, fmt.Errorf("unexpected argument %q: lock status takes no arguments", rest[0])
	}

	store, err := flags.open()
	if err != nil {
		return 1, err
	}
	summary, err := store.Summary()
	if err != nil {
		return 1, err
	}
	pending, err := store.Pending()
	if err != nil {
		return 1, err
	}

	if summary.Tools == 0 {
		fmt.Fprintf(out, "No tools recorded yet in %s.\nRun a server through mcp-audit first; its tools are pinned the first time they are seen.\n", store.Path())
		return 0, nil
	}

	fmt.Fprintf(out, "%d tool(s) pinned across %d server(s) (%s)\n", summary.Tools, summary.Servers, store.Path())
	if len(pending) == 0 {
		fmt.Fprintln(out, "Every tool matches what was approved.")
		return 0, nil
	}

	fmt.Fprintf(out, "\n%d tool(s) changed since they were approved:\n", len(pending))
	for _, p := range pending {
		fmt.Fprintf(out, "  %s / %s   %s -> %s   (changed %s)\n",
			p.Server, p.Tool, shortHash(p.ApprovedHash), shortHash(p.PendingHash),
			p.PendingSince.Format("2006-01-02 15:04 MST"))
	}
	fmt.Fprintln(out, "\nReview with `mcp-audit lock diff`, then accept with `mcp-audit lock approve`.")
	return 1, nil
}

func lockDiff(args []string, out io.Writer) (int, error) {
	fs := flag.NewFlagSet("lock diff", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var flags lockFlags
	flags.register(fs)
	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return 2, nil
	}
	server, tool, err := positional(rest)
	if err != nil {
		return 2, err
	}

	store, err := flags.open()
	if err != nil {
		return 1, err
	}
	pending, err := store.Pending()
	if err != nil {
		return 1, err
	}

	shown := 0
	for _, p := range pending {
		if (server != "" && p.Server != server) || (tool != "" && p.Tool != tool) {
			continue
		}
		shown++
		fmt.Fprintf(out, "%s / %s   %s -> %s\n", p.Server, p.Tool, shortHash(p.ApprovedHash), shortHash(p.PendingHash))

		lines := p.Diff()
		if p.Approved == nil || p.Pending == nil || !policy.HasChanges(lines) {
			fmt.Fprintln(out, "  (no readable snapshot of the approved version; compare the hashes above)")
		}
		for _, line := range lines {
			fmt.Fprintf(out, "  %s\n", line)
		}
		fmt.Fprintln(out)
	}

	if shown == 0 {
		fmt.Fprintln(out, "Nothing to review.")
	}
	return 0, nil
}

func lockApprove(args []string, out io.Writer) (int, error) {
	fs := flag.NewFlagSet("lock approve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var flags lockFlags
	flags.register(fs)
	all := fs.Bool("all", false, "approve every pending change")
	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return 2, nil
	}
	server, tool, err := positional(rest)
	if err != nil {
		return 2, err
	}

	// Approving is a security decision, so it has to be asked for by name. A bare
	// `lock approve` that quietly accepts everything would defeat the point.
	if !*all && server == "" {
		return 2, errors.New("say what to approve: `lock approve --all`, or `lock approve <server> [tool]` (see `lock status`)")
	}
	if *all && server != "" {
		return 2, errors.New("--all cannot be combined with a server name")
	}

	store, err := flags.open()
	if err != nil {
		return 1, err
	}
	approved, err := store.Approve(server, tool)
	if err != nil {
		return 1, err
	}
	if len(approved) == 0 {
		fmt.Fprintln(out, "Nothing was waiting for approval.")
		return 0, nil
	}

	for _, p := range approved {
		fmt.Fprintf(out, "approved %s / %s   %s -> %s\n", p.Server, p.Tool, shortHash(p.ApprovedHash), shortHash(p.PendingHash))
	}
	fmt.Fprintf(out, "%d change(s) approved. A running proxy picks this up on its next tools/list.\n", len(approved))
	return 0, nil
}

// parseInterspersed parses flags wherever they appear among the arguments and
// returns the positional ones in order.
//
// The standard flag package stops at the first non-flag argument, so
// `lock approve demo echo --state ./lock.json` would leave --state unparsed and
// act on the default store instead. For approval that is the worst way to be
// wrong: a security decision recorded, without complaint, in a file nobody
// asked about. So flags are accepted on either side of the server and tool.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positionals, nil
		}
		// "--" ends flag parsing for good; everything after it is positional.
		if args[0] == "--" {
			return append(positionals, args[1:]...), nil
		}
		positionals = append(positionals, args[0])
		args = args[1:]
	}
}

// positional returns the optional server and tool arguments. Anything beyond
// those two is an error rather than ignored: an argument that silently does
// nothing is usually a flag that was meant to do something.
func positional(args []string) (server, tool string, err error) {
	if len(args) > 2 {
		return "", "", fmt.Errorf("unexpected argument %q: expected at most a server and a tool", args[2])
	}
	if len(args) > 0 {
		server = args[0]
	}
	if len(args) > 1 {
		tool = args[1]
	}
	return server, tool, nil
}

func shortHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}
