#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$ROOT/.venv/bin/python"

if [[ ! -x "$PYTHON" ]]; then
  printf 'PromptGuard is not installed. Run ./install.sh from the repository root first.\n' >&2
  exit 1
fi
if ! command -v node >/dev/null 2>&1; then
  printf 'Node.js was not found.\n' >&2
  exit 1
fi
if ! command -v claude >/dev/null 2>&1; then
  printf 'Claude Code CLI was not found. Run ./install.sh for installation guidance.\n' >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  printf 'curl was not found.\n' >&2
  exit 1
fi

RUNTIME="$ROOT/.runtime"
AUDIT_DIR="$RUNTIME/audit"
mkdir -p "$AUDIT_DIR"

STAMP="$(date '+%Y%m%d-%H%M%S')"
PORT=$((30001 + RANDOM % 7999))
BRIDGE="$ROOT/src/detector/mcp-bridge.cjs"
MCP_CONFIG="$RUNTIME/mcp-$STAMP.json"

node -e 'const fs=require("fs"); const path=process.argv[1]; const bridge=process.argv[2]; fs.writeFileSync(path, JSON.stringify({mcpServers:{pgdetector:{command:"node",args:[bridge]}}}, null, 2), "utf8");' "$MCP_CONFIG" "$BRIDGE"

export PG_DETECTOR_PORT="$PORT"
export PG_DETECTOR_MODE="normal"
export PG_DETECTOR_URL="http://127.0.0.1:$PORT"
export PG_MOD_AUDIT="$AUDIT_DIR/mod-audit-$STAMP.json"
export PG_SESSION_HASH
PG_SESSION_HASH="$("$PYTHON" -c 'import hashlib, secrets; print(hashlib.sha256(secrets.token_bytes(32)).hexdigest())')"
export CLAUDE_CODE_ENABLE_FUNCTION_HOOKS="1"

WORKER="$ROOT/src/detector/worker.py"
WORKER_PID=""

stop_process_tree() {
  local parent_pid="$1"
  local child_pid

  for child_pid in $(pgrep -P "$parent_pid" 2>/dev/null || true); do
    stop_process_tree "$child_pid"
  done
  kill -TERM "$parent_pid" 2>/dev/null || true
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  if [[ -n "$WORKER_PID" ]]; then
    stop_process_tree "$WORKER_PID"
    wait "$WORKER_PID" 2>/dev/null || true
  fi
  exit "$status"
}

trap cleanup EXIT INT TERM HUP

(
  cd "$ROOT"
  exec "$PYTHON" "$WORKER"
) >"$RUNTIME/detector-$STAMP.stdout.log" 2>"$RUNTIME/detector-$STAMP.stderr.log" &
WORKER_PID=$!

READY=0
ATTEMPT=0
while [[ "$ATTEMPT" -lt 200 ]]; do
  if ! kill -0 "$WORKER_PID" 2>/dev/null; then
    break
  fi
  if curl --fail --silent --max-time 1 "$PG_DETECTOR_URL/health" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 0.1
  ATTEMPT=$((ATTEMPT + 1))
done

if [[ "$READY" -ne 1 ]]; then
  printf 'Detector worker failed to start. See %s\n' "$RUNTIME/detector-$STAMP.stderr.log" >&2
  exit 1
fi

printf 'PromptGuard Native Mod — demo mode\n'
printf 'Workspace: %s\n' "$(pwd)"
printf 'Raw-free audit: %s\n' "$PG_MOD_AUDIT"
curl --fail --silent --max-time 1 "$PG_DETECTOR_URL/health" | "$PYTHON" -c 'import json, sys
health = json.load(sys.stdin)
names = ", ".join(adapter["name"] for adapter in health["adapters"])
print("Detector: %s (consensus %s, %d vote(s) needed)" % (names, health["consensus"], health["required_votes"]))
for skipped in health["skipped"]:
    print("Detector: skipped %s (%s)" % (skipped["name"], skipped["reason"]))' || true
printf 'WARNING: this launcher is Mod-only; a provider-bound Final Guard is not included.\n' >&2

set +e
claude --plugin-dir "$ROOT/src/native-mod" --mcp-config "$MCP_CONFIG" "$@"
CLAUDE_STATUS=$?
set -e
exit "$CLAUDE_STATUS"
