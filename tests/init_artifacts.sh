#!/bin/bash
# Prepare integration-test artifacts:
#   - install host packages (qemu, libguestfs-tools, curl, jq, iproute2)
#   - download a Debian cloud image into artifacts/
#   - bake qemu-guest-agent into the image (the tests query the guest's
#     DHCP address through the QGA virtio-serial channel)
#
# Idempotent; re-run freely. The test scripts use artifacts/debian.qcow2.
set -euo pipefail
cd "$(dirname "$0")"

echo "[*] installing host packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq qemu-system-x86 qemu-utils libguestfs-tools cloud-image-utils curl jq iproute2 kmod wget socat

cd artifacts

# Debian
ARCH=amd64
VER=13
CODE=trixie
IMG=debian-$VER-backports-generic-$ARCH-daily.qcow2
if [ ! -f "$IMG" ]; then
    wget "https://cloud.debian.org/images/cloud/$CODE-backports/daily/latest/$IMG"
fi

# Baked-in packages: guest agent (the tests drive the guest through QGA),
# plus the tools later tests rely on (ping/iproute2/curl) and python3 for
# spinning up in-guest servers to exercise port forwarding.
STAMP="$IMG.customized.v2"
if [ ! -f "$STAMP" ]; then
    virt-customize -a "$IMG" \
        --install qemu-guest-agent,iputils-ping,iproute2,curl,python3
    touch "$STAMP"
else
    echo "[*] $IMG already customized, skipping virt-customize"
fi

ln -sf "$IMG" debian.qcow2

# NoCloud seed: without a cloud-init datasource the image configures no
# network and generates no ssh host keys. The seed turns on DHCP (cloud-init
# fallback) and sets a known password for debugging.
cat > user-data <<'EOF'
#cloud-config
ssh_pwauth: true
chpasswd:
  expire: false
  users:
    - name: root
      password: gvswitch
      type: text
EOF
cat > meta-data <<'EOF'
instance-id: gvswitch-test
local-hostname: gvswitch-test
EOF
cloud-localds seed.img user-data meta-data
echo "[+] artifacts ready: artifacts/debian.qcow2 -> $IMG, artifacts/seed.img"
