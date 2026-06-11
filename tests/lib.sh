#!/bin/bash
# Shared helpers for the gvswitch integration tests. Source this file.
# Each test gets a scratch dir, a built gvswitch on a unix control socket,
# and an `api` helper. Cleanup runs on exit.

set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$TESTS_DIR")"
ARTIFACTS="$TESTS_DIR/artifacts"
WORK="$(mktemp -d /tmp/gvswitch-test.XXXXXX)"

GVSWITCH_BIN="$WORK/gvswitch"
CTRL_SOCK="$WORK/ctrl.sock"
GVSWITCH_PID=""
QEMU_PID=""
CLEANUP_CMDS=()

log()  { echo "[*] $*"; }
ok()   { echo "[+] $*"; }
fail() { echo "[!] FAIL: $*" >&2; exit 1; }
skip() { echo "[-] SKIP: $*"; exit 0; }

add_cleanup() { CLEANUP_CMDS+=("$*"); }

cleanup() {
    set +e
    [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "$GVSWITCH_PID" ] && kill "$GVSWITCH_PID" 2>/dev/null
    local i
    for ((i = ${#CLEANUP_CMDS[@]} - 1; i >= 0; i--)); do
        eval "${CLEANUP_CMDS[$i]}" 2>/dev/null
    done
    rm -rf "$WORK"
}
trap cleanup EXIT

build_gvswitch() {
    log "building gvswitch"
    (cd "$REPO_DIR" && go build -o "$GVSWITCH_BIN" ./cmd/gvswitch)
}

start_gvswitch() {
    "$GVSWITCH_BIN" -listen "$CTRL_SOCK" "$@" &
    GVSWITCH_PID=$!
    wait_for 5 "[ -S '$CTRL_SOCK' ]" || fail "gvswitch control socket never appeared"
    ok "gvswitch running (pid $GVSWITCH_PID)"
}

# api METHOD PATH [JSON_BODY] -> response body; fails the test on HTTP >= 400.
api() {
    local method="$1" path="$2" body="${3:-}" out code
    if [ -n "$body" ]; then
        out=$(curl -sS --unix-socket "$CTRL_SOCK" -X "$method" -w '\n%{http_code}' \
            -d "$body" "http://gvswitch$path")
    else
        out=$(curl -sS --unix-socket "$CTRL_SOCK" -X "$method" -w '\n%{http_code}' \
            "http://gvswitch$path")
    fi
    code="${out##*$'\n'}"
    body="${out%$'\n'*}"
    if [ "$code" -ge 400 ]; then
        fail "API $method $path -> $code: $body"
    fi
    echo "$body"
}

# wait_for TIMEOUT_SECONDS "CONDITION" -> 0 when the condition becomes true.
wait_for() {
    local timeout="$1" cond="$2" waited=0
    until eval "$cond"; do
        sleep 1
        waited=$((waited + 1))
        [ "$waited" -ge "$timeout" ] && return 1
    done
    return 0
}

require_root() {
    [ "$(id -u)" = 0 ] || skip "requires root"
}

# create_gateway VLAN CIDR_GW (e.g. 100 10.0.100.2/24)
create_gateway() {
    local vlan="$1" addr="${2%/*}" plen="${2#*/}"
    api POST /api/v1/gateways \
        "{\"vlan\":$vlan,\"ipv4\":{\"address\":\"$addr\",\"prefix_len\":$plen}}" >/dev/null
    ok "gateway vlan=$vlan $2"
}

# enable_dhcp4 VLAN START END
enable_dhcp4() {
    api PUT "/api/v1/gateways/$1/dhcp4" \
        "{\"enabled\":true,\"pool_start\":\"$2\",\"pool_end\":\"$3\"}" >/dev/null
    ok "dhcp4 pool $2 - $3"
}

# qga_call QGA_SOCK JSON -> the command's response line from the qemu guest
# agent. Implements the canonical sync handshake: send guest-sync, discard
# stale buffered replies until the sync id comes back, then send the command
# and read exactly its reply.
qga_call() {
    timeout 10 python3 - "$1" "$2" <<'PYEOF' 2>/dev/null
import json, socket, sys
sock_path, cmd = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX)
s.settimeout(5)
s.connect(sock_path)
f = s.makefile("rw")
f.write(json.dumps({"execute": "guest-sync", "arguments": {"id": 4242}}) + "\n")
f.flush()
while True:
    line = f.readline()
    if not line:
        sys.exit(1)
    try:
        r = json.loads(line)
    except ValueError:
        continue
    if r.get("return") == 4242:
        break
f.write(cmd + "\n")
f.flush()
print(f.readline().strip())
PYEOF
}
