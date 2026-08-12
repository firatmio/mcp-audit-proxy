# mcp-audit

**Wireshark + auditd, but for MCP.**

`mcp-audit` sits transparently in front of any MCP server and records every
tool call that passes through it — what was called, by whom, with which
arguments, and what came back. One Go binary, no daemon, no Docker, no
Kubernetes.

It answers the question every team adopting agents eventually has to answer:
*which tool did our agent call, when, and with what?*

```console
$ mcp-audit run -- npx -y @modelcontextprotocol/server-filesystem /tmp
mcp-audit dev | mode: stdio, wrapping "npx -y @modelcontextprotocol/server-filesystem /tmp"
mcp-audit config: built-in defaults (no config file found)
mcp-audit policy: shadow (recording only, nothing is blocked)
mcp-audit detectors: rug-pull, tool-poisoning
mcp-audit audit log: /home/you/.mcp-audit/logs/events.jsonl
```

That is the whole setup. No config file, nothing blocked, everything recorded.

## Install

Build from source — Go 1.24 or newer, no other dependencies:

```bash
go build -o mcp-audit ./cmd/mcp-audit
```

Or install straight into your `GOBIN`:

```bash
go install github.com/firatmio/mcp-audit-proxy/cmd/mcp-audit@latest
```

## Quick start

### Local (stdio) MCP servers

Put `mcp-audit run --` in front of the command you already run:

```bash
mcp-audit run -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

### Remote (Streamable HTTP) MCP servers

Point the proxy at the upstream server and your client at the proxy:

```bash
mcp-audit serve --target https://example.com/mcp --listen :9000
```

Authentication is not touched: `Authorization` headers, OAuth flows and
`Mcp-Session-Id` all pass through exactly as they arrive.

### Read the log

Every message is one JSON line:

```console
$ tail -1 ~/.mcp-audit/logs/events.jsonl | jq
{
  "timestamp": "2026-08-12T13:05:08.466Z",
  "event_id": "236d1568-e1f0-4ab4-ba75-f10f74f7b2c9",
  "client_id": "",
  "server_name": "server-filesystem",
  "direction": "request",
  "method": "tools/call",
  "tool_name": "read_file",
  "arguments": { "path": "/etc/hosts" }
}
```

Some things you can do with it straight away:

```bash
# Which tools has this agent called, and how often?
jq -r 'select(.direction=="request" and .tool_name) | .tool_name' \
  ~/.mcp-audit/logs/events.jsonl | sort | uniq -c | sort -rn

# Show everything the policy engine flagged.
jq -c 'select(.policy_flags)' ~/.mcp-audit/logs/events.jsonl

# What arguments has a particular tool been called with?
jq -c 'select(.tool_name=="read_file") | {timestamp, arguments}' \
  ~/.mcp-audit/logs/events.jsonl
```

## Connecting your MCP client

See [`examples/clients/`](examples/clients/) for drop-in config snippets for
Claude Desktop, Cursor and Windsurf. The pattern is always the same: keep the
command you had, and put `mcp-audit run --` in front of it.

## What it detects

Recording is the default. These checks run on top of it and, apart from RBAC,
never block anything — they flag the event and print an alarm to stderr.

### Tool poisoning

A poisoned MCP server hides instructions in a tool *description*. The user only
sees a tool called `echo`; the model reads the rest. `mcp-audit` scans every
advertised description and schema field for seven patterns:

| Rule | What it looks for |
|---|---|
| `instruction_override` | "ignore all previous instructions" and variants |
| `hidden_instruction` | markup aimed at the model: `<IMPORTANT>`, `<system>`, `<secret>` |
| `concealment` | "do not tell the user", "without informing the user" |
| `credential_bait` | `~/.ssh`, `id_rsa`, `.env`, `~/.aws/credentials`, `/etc/shadow` |
| `exfiltration` | "send/upload/post …" with a URL nearby |
| `cross_tool_instruction` | orders about *other* tools — the tool-shadowing attack |
| `invisible_characters` | zero-width and bidi-override characters a human cannot see |

```console
mcp-audit: ALERT possible tool poisoning on server "demo": tool "echo" description matched hidden_instruction: "<IMPORTANT>"
mcp-audit: ALERT possible tool poisoning on server "demo": tool "echo" description matched concealment: "do not mention this to the user"
```

### Rug pulls

A rug pull is a server that advertises a harmless tool, waits for you to approve
it, and changes the description days later. `mcp-audit` fingerprints every tool
(SHA-256 over description + input schema) and remembers it in
`~/.mcp-audit/state/tools.json`, so the check survives restarts — which is the
only way it could ever catch the attack.

```console
mcp-audit: ALERT rug pull on server "demo": tool "read_file" changed its description or schema (first seen 2026-08-05T20:30:04Z, hash c203dda7a9ea -> 3f6e61538bfc)
```

### RBAC

The one check that can block. With no rules it allows everything; add a rule and
a refused call never reaches the server — the client gets a JSON-RPC error
instead.

```yaml
policy:
  rbac:
    default: allow
    rules:
      - client: "*"
        deny: ["shell_exec", "delete_*"]
```

```console
mcp-audit: blocked: tool "shell_exec" is denied by rule for client "*" (deny: "shell_exec")
```

## Configuration

Entirely optional. See [`config.example.yaml`](config.example.yaml) for the
annotated version. `mcp-audit` looks for a config file in this order:

1. `--config <path>`
2. `$MCP_AUDIT_CONFIG`
3. `./mcp-audit.yaml`
4. `~/.mcp-audit/config.yaml`

If it finds none, it uses built-in defaults and says so.

> **Windows paths in YAML:** write them with forward slashes
> (`"C:/Users/you/logs.jsonl"`) or in single quotes
> (`'C:\Users\you\logs.jsonl'`). Inside double quotes a backslash is a YAML
> escape character.

### Sending events elsewhere

The local JSONL log is always on. A webhook is optional and best-effort — if it
is down, delivery is retried four times over about three seconds and then that
event is dropped from that sink only. **The local log is never affected.**

```yaml
sinks:
  webhook:
    enabled: true
    url: "https://hooks.slack.com/services/T000/B000/xxx"
    # format and send are detected from the URL:
    # a Slack or Discord URL gets a chat-formatted message and, by default,
    # only flagged events. Anything else gets the raw JSON event and all of them.
```

## CLI reference

```
mcp-audit run [flags] -- <command> [args...]   wrap a local (stdio) MCP server
mcp-audit serve --target <url> [flags]         proxy a remote (HTTP) MCP server
mcp-audit version                              print the version

--config <path>       config file to use
--log <path>          audit log path, overriding the config
--server-name <name>  name recorded in every audit event
--client-id <id>      client identity recorded in every audit event
--quiet               suppress the startup banner

serve only:
--target <url>        upstream MCP server URL (required)
--listen <addr>       address to listen on (default ":9000")
```

## Design guarantees

- **Transparent.** Every byte the client sends reaches the server unchanged, and
  vice versa. The only exception is a call RBAC refuses.
- **The local log never loses an event.** It applies backpressure rather than
  dropping. Every other sink is best-effort and drops instead of slowing the
  proxy down.
- **Cheap.** Parsing costs about 8µs per tool-call round trip on a modern
  laptop — roughly 1/600th of the 5ms latency budget. See
  [`ARCHITECTURE.md`](ARCHITECTURE.md#performans-notu) for the measurements.
- **A message it cannot parse is still forwarded.** Auditing must never break a
  working MCP session.

## Demo

[`scripts/demo.sh`](scripts/demo.sh) runs the whole story end to end — a normal
session, a blocked call, a poisoned tool description and a rug pull — against
the stub server, in a temp directory that leaves your real state alone.

```bash
./scripts/demo.sh                                  # watch it
asciinema rec -c ./scripts/demo.sh mcp-audit.cast  # record it
```

`TYPING_SPEED=0 PAUSE=0 ./scripts/demo.sh` runs it instantly, which is handy as
a smoke test.

## Development

```bash
go test ./...                                       # everything
go test -race ./...                                 # concurrency
go test ./internal/interceptor/ -bench=. -benchmem  # performance
go build -o bin/dummy-mcp-server ./cmd/dummy-mcp-server
```

The race detector needs a C toolchain. On Windows, `scoop install mingw` (or
MSYS2) provides one; the performance assertion skips itself under `-race`,
since instrumented memory accesses measure the detector rather than the code.

`cmd/dummy-mcp-server` is a stub MCP server for testing the proxy against. It
speaks both stdio and Streamable HTTP and has flags for staging the attacks the
detectors look for:

```bash
mcp-audit run -- ./bin/dummy-mcp-server --poison     # poisoned tool description
mcp-audit run -- ./bin/dummy-mcp-server --rug-pull   # description changes after the first tools/list
./bin/dummy-mcp-server --http :8765                  # Streamable HTTP, for testing `serve`
```

Project context lives in [`CLAUDE.md`](CLAUDE.md), the module layout and data
model in [`ARCHITECTURE.md`](ARCHITECTURE.md), and the roadmap in
[`PLAN.md`](PLAN.md).
