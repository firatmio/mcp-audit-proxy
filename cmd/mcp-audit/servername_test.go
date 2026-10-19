package main

import "testing"

func TestDeriveServerName(t *testing.T) {
	cases := []struct {
		command []string
		want    string
	}{
		// Package runners: the package, not the runner.
		{[]string{"npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"}, "server-filesystem"},
		{[]string{"npx", "-y", "@modelcontextprotocol/server-github"}, "server-github"},
		{[]string{"npx", "@modelcontextprotocol/server-memory@2025.4.1"}, "server-memory"},
		{[]string{"npx", "-y", "mcp-remote@latest", "https://example.com/mcp"}, "mcp-remote"},
		{[]string{"npx", "--package", "@scope/tools", "tools-server"}, "tools-server"},
		{[]string{"npx", "-p=@scope/tools", "tools-server"}, "tools-server"},
		{[]string{"uvx", "mcp-server-fetch"}, "mcp-server-fetch"},
		{[]string{"uvx", "mcp-server-time==0.6.2", "--local-timezone=UTC"}, "mcp-server-time"},
		{[]string{"uvx", "--from", "git+https://github.com/org/repo-mcp.git", "repo-mcp"}, "repo-mcp"},
		{[]string{"bunx", "some-mcp"}, "some-mcp"},
		{[]string{"pnpm", "dlx", "@scope/pkg-mcp"}, "pkg-mcp"},
		{[]string{"npm", "exec", "--yes", "--", "@scope/pkg-mcp"}, "pkg-mcp"},
		{[]string{"pipx", "run", "mcp-server-git"}, "mcp-server-git"},

		// Windows spellings of the same runners.
		{[]string{`C:\Program Files\nodejs\npx.cmd`, "-y", "@modelcontextprotocol/server-filesystem"}, "server-filesystem"},
		{[]string{"NPX.CMD", "-y", "@scope/thing"}, "thing"},
		{[]string{`C:\Users\me\.local\bin\uvx.exe`, "mcp-server-fetch"}, "mcp-server-fetch"},

		// Containers: the image's repository name.
		{[]string{"docker", "run", "-i", "--rm", "-e", "GITHUB_TOKEN", "ghcr.io/github/github-mcp-server"}, "github-mcp-server"},
		{[]string{"docker", "run", "-i", "--rm", "-e", "A=b", "-v", "/x:/y", "mcp/fetch:latest"}, "fetch"},
		{[]string{"docker", "run", "--env=TOKEN=x", "mcp/time@sha256:abcd"}, "time"},

		// Interpreters: the script, or its project directory for an entry point.
		{[]string{"node", "/opt/weather-server/build/index.js"}, "weather-server"},
		{[]string{"node", `C:\mcp\weather-server\dist\index.js`}, "weather-server"},
		{[]string{"node", "--require", "dotenv/config", "/srv/notes.js"}, "notes"},
		{[]string{"python", "-m", "mcp_server_git", "--repository", "."}, "mcp_server_git"},
		{[]string{"python3", "/srv/my_tools/server.py"}, "my_tools"},
		{[]string{"python", "calc.py"}, "calc"},
		{[]string{"deno", "run", "--allow-net", "server.ts"}, "server"},
		{[]string{"deno", "run", "-A", "/srv/kv-store/main.ts"}, "kv-store"},
		{[]string{"bun", "run", "/srv/kv/index.ts"}, "kv"},

		// Everything else keeps the old behaviour.
		{[]string{"/usr/local/bin/my-mcp-server", "--stdio"}, "my-mcp-server"},
		{[]string{`C:\tools\dummy-mcp-server.exe`}, "dummy-mcp-server"},
		{[]string{"docker", "compose", "up"}, "docker"},
		{[]string{"npx"}, "npx"},
		{[]string{"npx", "-y"}, "npx"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := deriveServerName(c.command); got != c.want {
			t.Errorf("deriveServerName(%q) = %q, want %q", c.command, got, c.want)
		}
	}
}

func TestTwoNpxServersGetDifferentNames(t *testing.T) {
	// The bug this exists for: both used to be "npx", so they shared one set of
	// rug-pull fingerprints and `lock approve npx` approved both.
	a := deriveServerName([]string{"npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"})
	b := deriveServerName([]string{"npx", "-y", "@modelcontextprotocol/server-memory"})
	if a == b {
		t.Fatalf("two different npx servers share the name %q", a)
	}
}
