#!/bin/bash
# af_xdp transport: gvswitch takes over one end of a veth pair with AF_XDP;
# the peer end joins the switch network and must be able to ping the
# gateway.
source "$(dirname "$0")/lib.sh"
require_root

VETH=gvswxa
PEER=gvswxb
GW=10.0.151.2
HOSTIP=10.0.151.50

ip link del "$VETH" 2>/dev/null || true
ip link add "$VETH" type veth peer name "$PEER"
add_cleanup "ip link del $VETH"
ip link set "$VETH" up
ip link set "$PEER" up
ip addr add "$HOSTIP/24" dev "$PEER"

build_gvswitch
start_gvswitch

create_gateway 151 "$GW/24"
api POST /api/v1/ports \
    "{\"identifier\":\"xdp0\",\"vlan\":151,\"mode\":\"client\",\"transport\":\"af_xdp\",\"interface\":\"$VETH\"}" >/dev/null
ok "af_xdp port attached to $VETH"

log "pinging gateway $GW through $PEER"
ping -c 3 -W 2 -I "$PEER" "$GW" >/dev/null || fail "gateway unreachable via af_xdp"
ok "gateway answered ping"

STATS=$(api GET /api/v1/ports/xdp0 | jq .stats)
echo "$STATS" | jq -e '.rx_frames > 0 and .tx_frames > 0' >/dev/null \
    || fail "af_xdp stats not counting: $STATS"
ok "stats: $(echo "$STATS" | jq -c .)"

# Port deletion detaches the XDP program.
api DELETE /api/v1/ports/xdp0 >/dev/null
wait_for 5 "! ip link show $VETH | grep -q xdp" || fail "XDP program still attached"
ok "XDP program detached on port deletion"

ok "test_afxdp passed"
