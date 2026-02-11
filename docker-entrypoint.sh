#!/usr/bin/env bash
set -euo pipefail

python db/create_db_tables.py

flask --app run_mcp_server.py run --host 0.0.0.0 --port 5002 --no-debugger --no-reload &
MCP_PID=$!

flask --app run.py run --host 0.0.0.0 --port 5001 --no-debugger --no-reload &
WEB_PID=$!

shutdown() {
  kill -TERM "$MCP_PID" "$WEB_PID" 2>/dev/null || true
  wait "$MCP_PID" "$WEB_PID" 2>/dev/null || true
}

trap shutdown SIGTERM SIGINT

wait -n "$MCP_PID" "$WEB_PID"
EXIT_CODE=$?

shutdown
exit "$EXIT_CODE"
