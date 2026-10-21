#!/usr/bin/env bash
#
# A scripted mcp-audit demo, paced for screen recording.
#
#   vhs docs/demo.tape          # re-records docs/demo.gif
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
  # sleep is a separate process, which on Windows costs tens of milliseconds
  # even when told to sleep for 0: skip the loop entirely when not typing.
  if [ "$TYPING_SPEED" = 0 ]; then
    printf '%s\n' "$1"
  else
    local i
    for (( i=0; i<${#1}; i++ )); do
      printf '%s' "${1:i:1}"
      sleep "$TYPING_SPEED"
    done
    printf '\n'
  fi
  sleep 0.4
}

run() { type_out "$1"; eval "$1"; sleep "$PAUSE"; }

# run_check is run for a command whose exit status 1 is part of the story,
# such as `lock status` with changes pending. Any other failure still stops
# the script.
run_check() {
  type_out "$1"
  local status=0
  eval "$1" || status=$?
  [ "$status" -le 1 ] || exit "$status"
  sleep "$PAUSE"
}

# header starts a chapter on a clean screen, after a beat to finish reading the
# last one. A screen that never scrolls also keeps vhs recordings on Windows
# working: there, its picture stops updating once the output scrolls.
header() {
  sleep "$PAUSE"
  clear 2>/dev/null || true
  printf '%s%s────────  %s  ────────%s\n' "$BOLD" "$2" "$1" "$RESET"
}

# --- setup ------------------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

WORK="$(mktemp -d)"
trap 'cd "$REPO_ROOT"; rm -rf "$WORK"' EXIT

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

# The lock commands find the demo's config, and through it the demo's
# fingerprint store, the same way they would find yours: from the environment.
export MCP_AUDIT_CONFIG="$(topath "$WORK/config.yaml")"
# From here on, the log is just events.jsonl, which reads better on screen.
cd "$WORK"

# --- the demo ---------------------------------------------------------------

printf '%s%s  mcp-audit — a package-lock and flight recorder for MCP tools%s\n\n' "$BOLD" "$CYAN" "$RESET"
sleep "$PAUSE"

say "Put 'mcp-audit run --' in front of the MCP server you already run:"
type_out "mcp-audit run -- npx -y @modelcontextprotocol/server-filesystem /tmp"
sleep 0.6

say "Here a stub server keeps the demo self-contained. A normal session:"

session "" \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}'

say "Every message is now one JSON line in a local log. The tool call:"
run "grep -o '\"method\":\"tools/call\".*' events.jsonl"

# --- RBAC -------------------------------------------------------------------

header "Blocking a tool" "$YELLOW"
say "Only a rule you wrote can block. This config denies 'shell_exec':"

type_out 'echo {"method":"tools/call","params":{"name":"shell_exec",...}} | mcp-audit run -- ...'
printf '%s\n' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"rm -rf /"}}}' \
  | mcp-audit run $MCP_FLAGS -- "$DUMMY"
sleep "$PAUSE"

# --- poisoning --------------------------------------------------------------

header "Tool poisoning" "$RED"
say "The user sees a tool called 'echo'. The model is handed this:"

# stderr is silenced here so the description lands on its own; the alarms get
# their own beat below. The \uXXXX escapes are how Go encodes < and > in JSON.
printf '%s\n' '{"jsonrpc":"2.0","id":5,"method":"tools/list"}' \
  | mcp-audit run $POISON_FLAGS -- "$DUMMY" --poison 2>/dev/null \
  | grep -o '"description":"Echo[^"]*"' | head -1 \
  | sed 's/\\u003c/</g; s/\\u003e/>/g; s/^"description":"//; s/"$//' \
  | fold -w 76 -s
sleep "$PAUSE"

say "mcp-audit flags it, and lets it through:"
printf '%s\n' '{"jsonrpc":"2.0","id":5,"method":"tools/list"}' \
  | mcp-audit run $POISON_FLAGS -- "$DUMMY" --poison > /dev/null
sleep "$PAUSE"

# --- rug pull ---------------------------------------------------------------

header "Rug pull" "$RED"
say "The first server, days later, quietly changes a tool description:"

session "--rug-pull" \
  '{"jsonrpc":"2.0","id":6,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":7,"method":"tools/list"}'
sleep "$PAUSE"

say "The alarm repeats every session until a person reviews the change:"
run_check "mcp-audit lock status"
run "mcp-audit lock diff"
run "mcp-audit lock approve demo"

# --- close ------------------------------------------------------------------

printf '\n%s%s  Local only. One Go binary, Apache 2.0.%s\n' "$BOLD" "$CYAN" "$RESET"
printf '%s  github.com/firatmio/mcp-audit-proxy%s\n\n' "$CYAN" "$RESET"
sleep 2
