#!/bin/bash
# tap transport: gvswitch creates a tap device; the host side of the tap
# joins the switch network and must be able to ping the gateway.
source "$(dirname "$0")/lib.sh"
require_root

TAP=gvswtap0
GW=10.0.150.2
HOSTIP=10.0.150.50

build_gvswitch
start_gvswitch

create_gateway 150 "$GW/24"
api POST /api/v1/ports \
    "{\"identifier\":\"tap0\",\"vlan\":150,\"mode\":\"client\",\"transport\":\"tap\",\"tap_name\":\"$TAP\"}" >/dev/null
ok "tap port created ($TAP)"
add_cleanup "ip link del $TAP"

ip addr add "$HOSTIP/24" dev "$TAP"
ip link set "$TAP" up

log "pinging gateway $GW through $TAP"
ping -c 3 -W 2 -I "$TAP" "$GW" >/dev/null || fail "gateway unreachable via tap"
ok "gateway answered ping"

# The host MAC must now be in the FDB on vlan 150 via port tap0.
MAC=$(cat "/sys/class/net/$TAP/address")
ROW=$(api GET "/api/v1/fdb?vlan=150&mac=$MAC")
echo "$ROW" | jq -e --arg p tap0 '.[0].port == $p' >/dev/null || fail "FDB row missing: $ROW"
ok "FDB learned $MAC on tap0"

# Deleting the port removes the device.
api DELETE /api/v1/ports/tap0 >/dev/null
wait_for 5 "! ip link show $TAP >/dev/null 2>&1" || fail "$TAP still exists after port deletion"
ok "tap device removed with the port"

ok "test_tap passed"
