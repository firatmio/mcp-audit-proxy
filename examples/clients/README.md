# Connecting your MCP client through mcp-audit

The pattern is the same everywhere: **keep the command you already have, and put
`mcp-audit run --` in front of it.**

```diff
- "command": "npx",
- "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
+ "command": "mcp-audit",
+ "args": ["run", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
```

Nothing else changes. The client still talks to the same server over the same
stdio pipe; `mcp-audit` records what passes through.

## Where the config lives

| Client | Config file |
|---|---|
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop (Windows) | `%APPDATA%\Claude\claude_desktop_config.json` |
| Cursor (project) | `.cursor/mcp.json` in the project root |
| Cursor (global) | `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

Restart the client after editing. Check the file path against your client's
current documentation if it has moved — these move more often than you would
expect.

## Files here

- [`claude-desktop.json`](claude-desktop.json) — stdio and remote examples
- [`cursor.json`](cursor.json) — same, in Cursor's format
- [`windsurf.json`](windsurf.json) — same, in Windsurf's format

## Use an absolute path to the binary

GUI clients do not inherit your shell's `PATH`. If the client reports that it
cannot find `mcp-audit`, give it the full path:

- macOS/Linux: `/usr/local/bin/mcp-audit`, or `$(go env GOPATH)/bin/mcp-audit`
- Windows: `C:\\Users\\you\\go\\bin\\mcp-audit.exe` (note the doubled
  backslashes — this is JSON)

## Checking it works

After restarting the client, use any tool and then look at the log:

```bash
tail -f ~/.mcp-audit/logs/events.jsonl
```

If the file does not exist, the client is not running through the proxy. The
client's own MCP log will show `mcp-audit`'s startup banner on stderr, which is
the quickest way to confirm it launched.

## Remote (Streamable HTTP) servers

Clients cannot be told to wrap an HTTP server, so run the proxy separately and
point the client at it:

```bash
mcp-audit serve --target https://example.com/mcp --listen 127.0.0.1:9000
```

Then use `http://127.0.0.1:9000/mcp` as the server URL in your client. OAuth and
`Authorization` headers pass through untouched.

Bind to `127.0.0.1`, not `0.0.0.0`, unless you intend the proxy to be reachable
from the network: the audit log and the traffic through it contain tool
arguments, which routinely hold secrets.
