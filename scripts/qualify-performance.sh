#!/usr/bin/env bash
# Exercise representative local request paths with generous CI-safe budgets.
# This records timings and catches accidental hangs or whole-path regressions;
# it is not a machine-specific microbenchmark.
set -euo pipefail

binary=${FETCH_QUALIFY_BINARY:-}
if [[ -z "$binary" || ! -x "$binary" ]]; then
  printf 'FETCH_QUALIFY_BINARY must name an executable candidate\n' >&2
  exit 2
fi
command -v python3 >/dev/null 2>&1 || { echo 'python3 is required' >&2; exit 1; }
command -v timeout >/dev/null 2>&1 || { echo 'timeout is required' >&2; exit 1; }

root=$(mktemp -d "${TMPDIR:-/tmp}/fetch-performance.XXXXXX")
server_info="$root/server"
cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$root"
}
trap cleanup EXIT

python3 - "$server_info" <<'PY' &
import http.server
import pathlib
import sys
import threading

info = pathlib.Path(sys.argv[1])
large = b"x" * (8 * 1024 * 1024)

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/json":
            body = b'{"ok":true,"items":[1,2,3]}\n'
        elif self.path == "/large":
            body = large
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        remaining = length
        while remaining:
            chunk = self.rfile.read(min(remaining, 1024 * 1024))
            if not chunk:
                break
            remaining -= len(chunk)
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
info.write_text(str(server.server_port), encoding="ascii")
server.serve_forever()
PY
server_pid=$!
for _ in {1..100}; do
  [[ -s "$server_info" ]] && break
  sleep 0.01
done
[[ -s "$server_info" ]] || { echo 'performance fixture did not start' >&2; exit 1; }
base="http://127.0.0.1:$(<"$server_info")"

run_budget() {
  local name=$1 seconds=$2
  shift 2
  printf 'performance %-12s budget=%ss ' "$name" "$seconds"
  TIMEFORMAT='elapsed=%3R s'
  time timeout "${seconds}s" "$@"
}

run_budget startup 5 "$binary" --version >/dev/null
run_budget help 5 "$binary" --help >/dev/null
run_budget json 5 "$binary" --silent --output "$root/json" "$base/json"
run_budget download 20 "$binary" --silent --format off --output "$root/large" "$base/large"
python3 - "$root/upload" <<'PY'
import pathlib
import sys
pathlib.Path(sys.argv[1]).write_bytes(b"u" * (4 * 1024 * 1024))
PY
run_budget upload 20 "$binary" --silent --discard --data "@$root/upload" "$base/echo"

[[ "$(wc -c < "$root/large")" -eq $((8 * 1024 * 1024)) ]]
printf '%s\n' 'performance qualification passed'
