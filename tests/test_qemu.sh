#!/bin/bash
# Full-VM test: boot the Debian cloud image with its NIC backed by a
# gvswitch socket port, and verify end to end:
#   1. the guest obtains an address from the gateway's DHCPv4 server
#   2. the lease is tied to the switchport identifier
#   3. a dynamic local forward reaches the guest's sshd (SSH banner)
#   4. (via qemu-guest-agent) the guest really configured the leased IP
#
# TRANSPORT=stream (default) uses a unix stream port (qemu -netdev stream,
# QEMU 4-byte framing); TRANSPORT=dgram uses unixgram; TRANSPORT=tcp uses a
# tcp server port.
source "$(dirname "$0")/lib.sh"

IMAGE="$ARTIFACTS/debian.qcow2"
SEED="$ARTIFACTS/seed.img"
[ -f "$IMAGE" ] || skip "no $IMAGE; run ./init_artifacts.sh first"
[ -f "$SEED" ] || skip "no $SEED; run ./init_artifacts.sh first"
command -v qemu-system-x86_64 >/dev/null || skip "qemu-system-x86_64 not installed"

TRANSPORT="${TRANSPORT:-stream}"
GW=10.0.160.2
VLAN=160
MAC=52:54:00:de:ad:01
QGA_SOCK="$WORK/qga.sock"
FWD_PORT=18022

build_gvswitch
start_gvswitch
create_gateway $VLAN "$GW/24"
enable_dhcp4 $VLAN 10.0.160.100 10.0.160.199

NETDEV=""
MEMARGS=""
case "$TRANSPORT" in
vhost-user)
    VMSOCK="$WORK/vu.sock"
    api POST /api/v1/ports \
        "{\"identifier\":\"vm1\",\"vlan\":$VLAN,\"mode\":\"server\",\"transport\":\"vhost-user\",\"local\":\"$VMSOCK\"}" >/dev/null
    NETDEV="vhost-user,id=n0,chardev=c0"
    # vhost-user requires shared guest memory the backend can map.
    MEMARGS="-chardev socket,id=c0,path=$VMSOCK -object memory-backend-memfd,id=mem0,share=on,size=1024M -machine memory-backend=mem0"
    ;;
stream)
    VMSOCK="$WORK/vm.sock"
    api POST /api/v1/ports \
        "{\"identifier\":\"vm1\",\"vlan\":$VLAN,\"mode\":\"server\",\"transport\":\"unix\",\"local\":\"$VMSOCK\"}" >/dev/null
    NETDEV="stream,id=n0,server=off,addr.type=unix,addr.path=$VMSOCK"
    ;;
dgram)
    SWSOCK="$WORK/sw.sock"
    VMSOCK="$WORK/vm.sock"
    api POST /api/v1/ports \
        "{\"identifier\":\"vm1\",\"vlan\":$VLAN,\"mode\":\"server\",\"transport\":\"unixgram\",\"local\":\"$SWSOCK\"}" >/dev/null
    NETDEV="dgram,id=n0,local.type=unix,local.path=$VMSOCK,remote.type=unix,remote.path=$SWSOCK"
    ;;
tcp)
    TCPPORT=18610
    api POST /api/v1/ports \
        "{\"identifier\":\"vm1\",\"vlan\":$VLAN,\"mode\":\"server\",\"transport\":\"tcp\",\"local\":\"127.0.0.1:$TCPPORT\"}" >/dev/null
    NETDEV="stream,id=n0,server=off,addr.type=inet,addr.host=127.0.0.1,addr.port=$TCPPORT"
    ;;
*)
    fail "unknown TRANSPORT=$TRANSPORT"
    ;;
esac
ok "switchport vm1 ($TRANSPORT)"

ACCEL=""
[ -w /dev/kvm ] && ACCEL="-enable-kvm -cpu host"
log "booting debian VM ($TRANSPORT, $([ -n "$ACCEL" ] && echo kvm || echo tcg))"
# -snapshot keeps the artifact image pristine.
qemu-system-x86_64 \
    -m 1024 -smp 2 $ACCEL $MEMARGS \
    -snapshot -display none -serial null -monitor none \
    -drive file="$IMAGE",if=virtio,format=qcow2 \
    -drive file="$SEED",if=virtio,format=raw \
    -netdev "$NETDEV" \
    -device virtio-net-pci,netdev=n0,mac=$MAC \
    -chardev socket,path="$QGA_SOCK",server=on,wait=off,id=qga0 \
    -device virtio-serial -device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0 \
    &
QEMU_PID=$!

BOOT_TIMEOUT="${BOOT_TIMEOUT:-300}"
log "waiting for DHCP lease (up to ${BOOT_TIMEOUT}s)"
wait_for "$BOOT_TIMEOUT" \
    "api GET /api/v1/gateways/$VLAN/dhcp4/leases | jq -e 'length > 0' >/dev/null" \
    || fail "guest never obtained a DHCP lease"

LEASE=$(api GET "/api/v1/gateways/$VLAN/dhcp4/leases" | jq -r '.[0]')
GUEST_IP=$(echo "$LEASE" | jq -r .ip)
LEASE_PORT=$(echo "$LEASE" | jq -r .port_identifier)
LEASE_MAC=$(echo "$LEASE" | jq -r .mac)
ok "lease: $GUEST_IP mac=$LEASE_MAC port=$LEASE_PORT"
[ "$LEASE_PORT" = vm1 ] || fail "lease not tied to switchport: $LEASE"
[ "$LEASE_MAC" = "$MAC" ] || fail "lease MAC mismatch: $LEASE"

# Cross-check via the guest agent (best effort: the SSH check below is the
# authoritative proof that the guest configured the leased address).
QGA_UP=0
if wait_for 90 "qga_call '$QGA_SOCK' '{\"execute\":\"guest-network-get-interfaces\"}' | grep -q '\"$GUEST_IP\"'"; then
    ok "guest agent confirms $GUEST_IP configured in guest"
    QGA_UP=1
else
    log "guest agent did not confirm the address (non-fatal)"
fi

# Dynamic local forward host:18022 -> guest:22, expect the SSH banner.
api POST "/api/v1/gateways/$VLAN/forwards" \
    "{\"type\":\"local\",\"network\":\"tcp\",\"bind\":\"127.0.0.1:$FWD_PORT\",\"host\":\"$GUEST_IP:22\"}" >/dev/null
log "waiting for sshd via local forward"
wait_for 120 "timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/$FWD_PORT; head -c 4 <&3' 2>/dev/null | grep -q SSH-" \
    || fail "no SSH banner through the local forward"
ok "SSH banner received through gateway local forward"

# Expose a service running *inside* the VM to the outside world: start a
# python http server in the guest (via the guest agent) and reach it from
# the host through a dynamic local forward.
if [ "$QGA_UP" = 1 ]; then
    HTTP_FWD_PORT=18080
    qga_call "$QGA_SOCK" '{"execute":"guest-exec","arguments":{"path":"/usr/bin/python3","arg":["-m","http.server","8000","--directory","/etc"]}}' \
        | grep -q pid || fail "guest-exec failed to start python http.server"
    api POST "/api/v1/gateways/$VLAN/forwards" \
        "{\"type\":\"local\",\"network\":\"tcp\",\"bind\":\"127.0.0.1:$HTTP_FWD_PORT\",\"host\":\"$GUEST_IP:8000\"}" >/dev/null
    log "waiting for in-guest http server via local forward"
    wait_for 60 "curl -sf --max-time 5 http://127.0.0.1:$HTTP_FWD_PORT/hostname | grep -q ." \
        || fail "in-guest http server unreachable through the local forward"
    HOSTNAME_SEEN=$(curl -sf --max-time 5 "http://127.0.0.1:$HTTP_FWD_PORT/hostname")
    ok "in-guest http server exposed to host; /etc/hostname = $HOSTNAME_SEEN"
else
    log "guest agent unavailable; skipping in-guest http server check"
fi

# Killing the VM (port offline) must release the lease automatically.
kill "$QEMU_PID"
wait "$QEMU_PID" 2>/dev/null || true
QEMU_PID=""
if [ "$TRANSPORT" != dgram ]; then # datagram transports have no disconnect signal
    wait_for 15 "api GET /api/v1/gateways/$VLAN/dhcp4/leases | jq -e 'length == 0' >/dev/null" \
        || fail "lease not released after VM shutdown"
    ok "lease auto-released on port offline"
fi

ok "test_qemu ($TRANSPORT) passed"
