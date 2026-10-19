# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`mcp-audit lock`.** `lock status` lists tools whose description or schema
  changed since they were approved (exit status 1 if any, so CI can gate on
  it), `lock diff` shows the change sentence by sentence, and
  `lock approve --all` / `lock approve <server> [tool]` accepts it. Think
  package-lock, for MCP tool descriptions.
- The fingerprint store now keeps a readable snapshot of each approved tool, so
  a change can be reviewed rather than only detected. Stores written by 0.1.0
  keep working; snapshots are filled in the next time a tool is seen unchanged.

### Removed

- **The hosted sink.** mcp-audit is fully open source and has no paid tier or
  hosted backend. Config files that contain a `sinks.hosted` section still load;
  `enabled: true` there is now an error that points to the webhook sink
  (`format: generic`, `send: all`) for forwarding events to your own collector.

### Fixed

- **A rug pull alarmed only once.** The baseline used to move to the new hash
  as soon as a change was seen, so the second session looked clean. The
  approved version now stays the baseline and the alarm repeats on every
  session until the change is approved or reverted.
- The proxy re-reads the store on every `tools/list`, so an approval made with
  `lock approve` while a proxy is running is not overwritten.
- **`lock` flags after the server name were ignored.** `lock approve demo echo
  --state ./lock.json` stopped parsing at `demo`, dropped `--state`, and
  approved the change in the default store instead — without saying so. Flags
  are now accepted on either side of the server and tool, and a surplus
  argument is an error rather than silently discarded.

## [0.1.0] — 2026-08-13

First release.

### Recording

- **stdio mode.** `mcp-audit run -- <command>` wraps a local MCP server. Bytes
  pass through untouched in both directions; a message the parser cannot
  understand is still forwarded, because auditing should never be the reason a
  working session breaks.
- **HTTP mode.** `mcp-audit serve --target <url>` proxies a Streamable HTTP
  server. Both plain JSON and `text/event-stream` responses are audited, the
  latter tapped as it streams rather than buffered. Authorization headers,
  OAuth flows and `Mcp-Session-Id` pass through untouched.
- **Local JSONL log**, always on, one line per JSON-RPC message, at
  `~/.mcp-audit/logs/events.jsonl`. It applies backpressure rather than
  dropping: no other sink can cost it an event.
- **Zero config.** With no config file, everything is recorded and nothing is
  blocked.

### Detecting

- **Tool poisoning heuristics.** Seven rules over tool descriptions and schema
  field descriptions: instruction overrides, markup aimed at the model,
  concealment phrasing, credential-file references, exfiltration URLs,
  cross-tool instructions, and invisible Unicode.
- **Rug-pull detection.** SHA-256 fingerprints of every tool's description and
  input schema, persisted to `~/.mcp-audit/state/tools.json` so the check
  survives restarts — which is the only way it could catch an attack that
  happens days after you approved the tool. Schemas are canonicalised first, so
  a server that reorders its JSON keys is not mistaken for an attacker.
- **RBAC.** Optional allow/deny rules, the one check that can block a call.
  Deny always wins over allow, and a non-empty allow list is exhaustive. A
  blocked call never reaches the server; the client gets a JSON-RPC error.

Neither detector blocks. They flag the event and print an alarm, because by the
time a `tools/list` result comes back the evidence is what matters.

### Shipping events elsewhere

- **Webhook sink**, optional and best-effort. Slack, Discord and generic
  formats, detected from the URL. Chat formats default to flagged events only;
  a generic SIEM feed gets everything.
- **Hosted sink**, optional and best-effort. Batches events to a remote
  ingest endpoint, gzipped. Refuses plain HTTP outside loopback. (Removed in
  the next release.)
- Both retry with bounded exponential backoff and drop rather than slow the
  proxy down.

### Performance

Parsing adds about 8µs to a tool-call round trip on a modern laptop, against
the 5ms budget in `ARCHITECTURE.md`. A test fails if the p99 regresses.

### Known limitations

- The poisoning rules are heuristics. They raise the cost of a lazy attack and
  leave an audit trail for a careful one; they are not a guarantee.
- JSON-RPC batches are audited but never blocked. A batch carries several ids
  and current MCP no longer uses them, so a partial refusal would be more
  surprising than useful.
- HTTP mode treats `--target` as the endpoint itself, sending every request
  there whatever local path the client used. This is correct for
  single-endpoint Streamable HTTP and does not support the older two-endpoint
  HTTP+SSE transport.
- Request and response bodies over 8 MiB are proxied untouched but not audited.

[0.1.0]: https://github.com/firatmio/mcp-audit-proxy/releases/tag/v0.1.0
