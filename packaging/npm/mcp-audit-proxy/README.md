# mcp-audit-proxy

A transparent audit proxy for MCP servers. Put it in front of any MCP server and
every tool call is recorded — what was called, by whom, with which arguments,
and what came back.

```bash
npx mcp-audit-proxy run -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

Or install it so the `mcp-audit` command is on your PATH:

```bash
npm install -g mcp-audit-proxy
mcp-audit run -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

This package is a thin launcher. The real program is a single Go binary,
shipped as a per-platform optional dependency — there is no postinstall
download, so `npm install --ignore-scripts` works normally.

Prefer not to involve npm at all? The binary stands alone:

```bash
go install github.com/firatmio/mcp-audit-proxy/cmd/mcp-audit@latest
```

Full documentation, configuration and the security detectors:
**https://github.com/firatmio/mcp-audit-proxy**
