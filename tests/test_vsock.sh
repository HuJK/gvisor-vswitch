#!/bin/bash
# vsock transport over the kernel's vsock loopback (CID 1): two gvswitch
# instances linked by a vsock stream connection.
#
#   host(ping) -> tap(B) -> switch B -> vsock client ----loopback----
#       ----> vsock server -> switch A -> gateway (answers ping)
source "$(dirname "$0")/lib.sh"
require_root

modprobe vsock_loopback 2>/dev/null || true
[ -e /dev/vsock ] || skip "no /dev/vsock (vsock_loopback module unavailable)"

GW=10.0.152.2
HOSTIP=10.0.152.50
TAP=gvswvst0
VPORT=10152

build_gvswitch

# Instance A: vsock server + gateway.
start_gvswitch
create_gateway 152 "$GW/24"
api POST /api/v1/ports \
    "{\"identifier\":\"vs-srv\",\"vlan\":152,\"mode\":\"server\",\"transport\":\"vsock\",\"local\":\":$VPORT\"}" >/dev/null
ok "instance A: vsock server on port $VPORT"

# Instance B: separate control socket; vsock client to CID 1 + tap.
CTRL_B="$WORK/ctrl-b.sock"
"$GVSWITCH_BIN" -listen "$CTRL_B" &
GVSWITCH_B_PID=$!
add_cleanup "kill $GVSWITCH_B_PID"
wait_for 5 "[ -S '$CTRL_B' ]" || fail "instance B control socket never appeared"

api_b() {
    local method="$1" path="$2" body="${3:-}" out code
    out=$(curl -sS --unix-socket "$CTRL_B" -X "$method" -w '\n%{http_code}' \
        ${body:+-d "$body"} "http://gvswitch$path")
    code="${out##*$'\n'}"
    [ "$code" -ge 400 ] && fail "API(B) $method $path -> $code: ${out%$'\n'*}"
    echo "${out%$'\n'*}"
}

api_b POST /api/v1/ports \
    "{\"identifier\":\"vs-cli\",\"vlan\":152,\"mode\":\"client\",\"transport\":\"vsock\",\"remote\":\"1:$VPORT\"}" >/dev/null
ok "instance B: vsock client connected via loopback"

api_b POST /api/v1/ports \
    "{\"identifier\":\"tap0\",\"vlan\":152,\"mode\":\"client\",\"transport\":\"tap\",\"tap_name\":\"$TAP\"}" >/dev/null
add_cleanup "ip link del $TAP"
ip addr add "$HOSTIP/24" dev "$TAP"
ip link set "$TAP" up

log "pinging gateway $GW across the vsock link"
ping -c 3 -W 3 -I "$TAP" "$GW" >/dev/null || fail "gateway unreachable across vsock"
ok "gateway answered ping across tap -> switch B -> vsock -> switch A -> gateway"

# The vsock server port must report its peer (CID:port form).
PEER=$(api GET /api/v1/ports/vs-srv | jq -r .peer)
[ -n "$PEER" ] && [ "$PEER" != null ] || fail "vsock server has no peer"
ok "vsock server peer: $PEER"

ok "test_vsock passed"
