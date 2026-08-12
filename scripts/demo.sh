#!/usr/bin/env bash
#
# A scripted mcp-audit demo, paced for screen recording.
#
#   asciinema rec -c ./scripts/demo.sh mcp-audit.cast
#   agg mcp-audit.cast mcp-audit.gif          # if you want a GIF
#
# Or just run it to watch:
#
#   ./scripts/demo.sh
#
# It builds the binaries into a temp directory and uses a temp audit log, so it
# never touches your real ~/.mcp-audit state.

set -euo pipefail

# --- presentation helpers ---------------------------------------------------

BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
YELLOW=$'\033[33m'; CYAN=$'\033[36m'; RESET=$'\033[0m'

# TYPING_SPEED is the per-character delay for the fake typing. Set it to 0 for
# an instant run when you are only testing the script.
TYPING_SPEED="${TYPING_SPEED:-0.02}"
PAUSE="${PAUSE:-1.2}"

say() { printf '\n%s# %s%s\n' "$DIM" "$1" "$RESET"; sleep "$PAUSE"; }

# type_out prints a command one character at a time, so a recording looks like
# someone is at the keyboard.
type_out() {
  printf '%s$%s ' "$GREEN" "$RESET"
  local i
  for (( i=0; i<${#1}; i++ )); do
    printf '%s' "${1:i:1}"
    sleep "$TYPING_SPEED"
  done
  printf '\n'
  sleep 0.4
}

run() { type_out "$1"; eval "$1"; sleep "$PAUSE"; }

# --- setup ------------------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

BIN="$WORK/bin"
LOG="$WORK/events.jsonl"
STATE="$WORK/tools.json"
mkdir -p "$BIN"

# go build writes exactly the -o path, so on Windows we have to ask for the
# .exe ourselves or the result is not executable.
EXE=""
case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*) EXE=".exe" ;;
esac

DUMMY="$BIN/dummy-mcp-server$EXE"

# Under Git Bash the binaries are native Windows programs, so a POSIX path like
# /tmp/x would be resolved against the current drive (C:\tmp\x). cygpath -m
# gives the mixed form (C:/tmp/x), which Windows understands and which is also
# safe inside YAML double quotes — a backslash there would be an escape.
topath() {
  if [ -n "$EXE" ]; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

printf '%s%sBuilding...%s\n' "$BOLD" "$CYAN" "$RESET"
go build -o "$BIN/mcp-audit$EXE" ./cmd/mcp-audit
go build -o "$DUMMY" ./cmd/dummy-mcp-server
export PATH="$BIN:$PATH"
# No TTY in CI, where this script doubles as an end-to-end smoke test.
clear 2>/dev/null || true

# A config that keeps everything inside the temp directory.
cat > "$WORK/config.yaml" <<EOF
policy:
  state_path: "$(topath "$STATE")"
  rbac:
    default: allow
    rules:
      - client: "*"
        deny: ["shell_exec"]
sinks:
  jsonl:
    path: "$(topath "$LOG")"
EOF

# The poisoning demo gets its own fingerprint store. Sharing one with the
# honest session would make the poisoned server also trip the rug-pull
# detector, which is true but muddles two separate stories.
sed "s|$(topath "$STATE")|$(topath "$WORK/poison-tools.json")|" \
  "$WORK/config.yaml" > "$WORK/poison.yaml"

# Flags belong to the subcommand, after `run`.
MCP_FLAGS="--config $(topath "$WORK/config.yaml") --quiet --server-name demo"
POISON_FLAGS="--config $(topath "$WORK/poison.yaml") --quiet --server-name demo"

# session pipes a set of JSON-RPC messages through the proxy.
session() {
  local server_flags="$1"; shift
  printf '%s\n' "$@" | mcp-audit run $MCP_FLAGS -- \
    "$DUMMY" $server_flags > /dev/null
}

# --- the demo ---------------------------------------------------------------

printf '%s%s  mcp-audit — Wireshark + auditd, but for MCP%s\n\n' "$BOLD" "$CYAN" "$RESET"
sleep "$PAUSE"

say "You have an MCP server. You run it like this today:"
type_out "npx -y @modelcontextprotocol/server-filesystem /tmp"
sleep 0.6

say "To audit it, put 'mcp-audit run --' in front. That is the whole setup."
type_out "mcp-audit run -- npx -y @modelcontextprotocol/server-filesystem /tmp"
sleep 0.6

say "Let's use a stub server so the demo is self-contained."
say "First, a normal session: list the tools, then call one."

session "" \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}'

say "Every message is now one JSON line on disk."
run "tail -2 $LOG | cut -c1-160"

say "Which tools has this agent called?"
run "grep -o '\"tool_name\":\"[^\"]*\"' $LOG | sort | uniq -c"

# --- RBAC -------------------------------------------------------------------

printf '\n%s%s────────  Blocking a tool  ────────%s\n' "$BOLD" "$YELLOW" "$RESET"
say "The config denies 'shell_exec'. Watch what the client gets back."

type_out 'echo {"method":"tools/call","params":{"name":"shell_exec",...}} | mcp-audit run -- ...'
printf '%s\n' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"rm -rf /"}}}' \
  | mcp-audit run $MCP_FLAGS -- "$DUMMY"
sleep "$PAUSE"

say "The call never reached the server. The client got a JSON-RPC error."

# --- poisoning --------------------------------------------------------------

printf '\n%s%s────────  Tool poisoning  ────────%s\n' "$BOLD" "$RED" "$RESET"
say "Now a server whose tool description hides instructions for the model."
say "The user only ever sees a tool called 'echo'. Here is the description"
say "the model is handed:"

# stderr is silenced here so the description lands on its own; the alarms get
# their own beat below. The \uXXXX escapes are how Go encodes < and > in JSON.
printf '%s\n' '{"jsonrpc":"2.0","id":5,"method":"tools/list"}' \
  | mcp-audit run $POISON_FLAGS -- "$DUMMY" --poison 2>/dev/null \
  | grep -o '"description":"Echo[^"]*"' | head -1 \
  | sed 's/\\u003c/</g; s/\\u003e/>/g; s/^"description":"//; s/"$//' \
  | fold -w 76 -s
sleep "$PAUSE"

say "mcp-audit reads it too:"
printf '%s\n' '{"jsonrpc":"2.0","id":5,"method":"tools/list"}' \
  | mcp-audit run $POISON_FLAGS -- "$DUMMY" --poison > /dev/null
sleep "$PAUSE"

# --- rug pull ---------------------------------------------------------------

printf '\n%s%s────────  Rug pull  ────────%s\n' "$BOLD" "$RED" "$RESET"
say "The nastier one: a server that was honest when you approved it,"
say "and changes a tool description days later. We fingerprinted it the"
say "first time, in a completely different process."

session "--rug-pull" \
  '{"jsonrpc":"2.0","id":6,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":7,"method":"tools/list"}'
sleep "$PAUSE"

say "Everything flagged is in the audit log, with the evidence attached."
run "grep -c policy_flags $LOG | xargs echo 'flagged events:'"

# --- close ------------------------------------------------------------------

printf '\n%s%s  One binary. No daemon, no Docker.%s\n' "$BOLD" "$CYAN" "$RESET"
printf '%s  github.com/firatmio/mcp-audit-proxy%s\n\n' "$CYAN" "$RESET"
sleep 2
