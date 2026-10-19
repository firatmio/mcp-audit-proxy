package main

import (
	"path/filepath"
	"strings"
)

// The server name is not cosmetic. It is the key the rug-pull fingerprints are
// stored under, so two different servers that end up with the same name share
// one set of fingerprints: `lock approve` for one approves the other, and a
// tool one of them defines can look like a "change" to the other's tool of the
// same name.
//
// Naming a server after the program that was executed gets this wrong for the
// most common way MCP servers are launched. With `npx -y @scope/server-a` and
// `npx -y @scope/server-b` both servers were "npx". So when the program is a
// package runner, an interpreter or `docker run`, the name comes from what it
// runs instead. Anything not recognised keeps the old behaviour, and
// --server-name always wins.

// packageRunners run their first positional argument as a package.
var packageRunners = map[string]bool{
	"npx": true, "bunx": true, "pnpx": true, "uvx": true,
}

// subcommandRunners are package runners spelled as a tool plus a subcommand.
var subcommandRunners = map[string]string{
	"pnpm": "dlx", "yarn": "dlx", "npm": "exec", "pipx": "run", "bun": "x",
}

// scriptInterpreters run their first positional argument as a script file.
var scriptInterpreters = map[string]bool{
	"node": true, "python": true, "python3": true, "py": true, "deno": true, "bun": true,
}

// flagsWithValue lists, per launcher, the flags that consume the next
// argument. Without this, `docker run -e TOKEN=x image` would read "TOKEN=x"
// as the image. A flag written as --flag=value never consumes the next one.
var flagsWithValue = map[string]map[string]bool{
	"npx":  {"-p": true, "--package": true, "-c": true, "--call": true},
	"pnpx": {"-p": true, "--package": true, "-c": true},
	"bunx": {"-p": true, "--package": true},
	"uvx": {"--from": true, "--with": true, "--python": true, "-p": true,
		"--index": true, "--index-url": true, "--extra-index-url": true},
	"dlx":  {"-p": true, "--package": true, "-c": true},
	"exec": {"-p": true, "--package": true, "-c": true, "--call": true},
	"run":  {"--spec": true, "--python": true, "--pip-args": true},
	"x":    {"-p": true, "--package": true},
	"docker": {"-e": true, "--env": true, "--env-file": true, "-v": true, "--volume": true,
		"--mount": true, "-p": true, "--publish": true, "--name": true, "-w": true,
		"--workdir": true, "--network": true, "--net": true, "-u": true, "--user": true,
		"--entrypoint": true, "-l": true, "--label": true, "--platform": true,
		"--pull": true, "-m": true, "--memory": true, "--cpus": true, "-h": true,
		"--hostname": true, "--add-host": true, "--cap-add": true, "--cap-drop": true,
		"--security-opt": true, "--tmpfs": true, "--device": true, "--runtime": true,
		"--log-driver": true, "--restart": true, "--ulimit": true, "--shm-size": true},
	"node":    {"-r": true, "--require": true, "--import": true, "--loader": true, "-e": true, "--eval": true},
	"python":  {"-W": true, "-X": true, "-c": true},
	"python3": {"-W": true, "-X": true, "-c": true},
	"py":      {"-W": true, "-X": true, "-c": true},
	"deno":    {"--config": true, "-c": true, "--import-map": true},
	"bun":     {"--cwd": true, "--config": true},
}

// deriveServerName picks a name for a stdio server from its command line.
func deriveServerName(command []string) string {
	if len(command) == 0 {
		return ""
	}
	program := programName(command[0])
	fallback := program
	args := command[1:]

	launcher := program
	if sub, ok := subcommandRunners[program]; ok && len(args) > 0 && args[0] == sub {
		launcher, args = sub, args[1:]
	} else if program == "docker" {
		if len(args) == 0 || args[0] != "run" {
			return fallback
		}
		args = args[1:]
	}

	switch {
	case packageRunners[launcher] || launcher != program:
		if name := cleanPackage(firstPositional(launcher, args)); name != "" {
			return name
		}

	case program == "docker":
		if name := cleanImage(firstPositional("docker", args)); name != "" {
			return name
		}

	case scriptInterpreters[program]:
		// `python -m mcp_server_git` names a module, not a file.
		if program == "python" || program == "python3" || program == "py" {
			for i, a := range args {
				if a == "-m" && i+1 < len(args) {
					return args[i+1]
				}
			}
		}
		script := firstPositional(program, args)
		// `deno run x.ts` and `bun run x.ts`: the script follows the verb.
		if (program == "bun" || program == "deno") && script == "run" {
			script = firstPositional(program, args[indexOf(args, "run")+1:])
		}
		if name := scriptName(script); name != "" {
			return name
		}
	}
	return fallback
}

// programName reduces an executable path to a bare lowercase name, so that
// `C:\Program Files\nodejs\npx.cmd` and `/usr/bin/npx` are both "npx".
func programName(path string) string {
	// filepath.Base only splits on the host's separator; a Windows path can
	// arrive on any host inside a shared client config.
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		path = path[i+1:]
	}
	path = strings.ToLower(path)
	for _, ext := range []string{".exe", ".cmd", ".bat", ".ps1"} {
		path = strings.TrimSuffix(path, ext)
	}
	return path
}

// firstPositional returns the first argument that is neither a flag nor a
// flag's value. It stops at "--", after which the next argument is positional.
func firstPositional(launcher string, args []string) string {
	takesValue := flagsWithValue[launcher]
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			if !strings.Contains(a, "=") && takesValue[a] {
				i++
			}
			continue
		}
		return a
	}
	return ""
}

// cleanPackage turns a package spec into a readable name:
// "@modelcontextprotocol/server-filesystem@1.2.0" -> "server-filesystem",
// "mcp-server-fetch==0.6" -> "mcp-server-fetch".
func cleanPackage(spec string) string {
	if spec == "" {
		return ""
	}
	// A git or URL spec: the repository name is the useful part.
	if strings.Contains(spec, "://") || strings.HasPrefix(spec, "git+") {
		spec = strings.TrimSuffix(strings.TrimRight(spec, "/"), ".git")
		if i := strings.LastIndex(spec, "/"); i >= 0 {
			spec = spec[i+1:]
		}
		return spec
	}
	// Drop a version: "@1.2.0" after the name (but not the leading "@" of a
	// scope), or a Python specifier.
	if i := strings.LastIndex(spec, "@"); i > 0 {
		spec = spec[:i]
	}
	if i := strings.IndexAny(spec, "=<>~![;"); i > 0 {
		spec = spec[:i]
	}
	// Drop the npm scope.
	if i := strings.LastIndex(spec, "/"); i >= 0 {
		spec = spec[i+1:]
	}
	return spec
}

// cleanImage turns an image reference into its repository name:
// "ghcr.io/github/github-mcp-server:latest" -> "github-mcp-server".
func cleanImage(ref string) string {
	if ref == "" {
		return ""
	}
	if i := strings.Index(ref, "@"); i >= 0 { // digest
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		ref = ref[i+1:]
	}
	if i := strings.Index(ref, ":"); i >= 0 { // tag
		ref = ref[:i]
	}
	return ref
}

// scriptName names a server after its script, using the directory when the
// file is a generic entry point: ".../weather-server/index.js" -> "weather-server".
func scriptName(script string) string {
	if script == "" {
		return ""
	}
	script = strings.ReplaceAll(script, `\`, "/")
	base := filepath.Base(script)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	switch strings.ToLower(name) {
	case "index", "main", "server", "app", "__main__", "cli", "mod":
		dir := filepath.Base(filepath.Dir(script))
		// Skip build-output directories to reach the project's own name.
		for _, generic := range []string{"dist", "build", "src", "lib", "bin", "out"} {
			if strings.EqualFold(dir, generic) {
				dir = filepath.Base(filepath.Dir(filepath.Dir(script)))
				break
			}
		}
		if dir != "." && dir != "/" && dir != "" {
			return dir
		}
	}
	return name
}

func indexOf(args []string, want string) int {
	for i, a := range args {
		if a == want {
			return i
		}
	}
	return -1
}
