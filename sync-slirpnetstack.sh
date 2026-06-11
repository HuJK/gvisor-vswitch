#!/bin/sh
# Sync the slirpnetstack checkout with upstream and convert it into an
# importable library: package main -> package slirpnetstack, plus the
# vswitch glue file from overlay/ which re-exports package-internal
# symbols needed by the gateway.
#
# Run this after every upstream update. The final `go build` is the
# guard: if upstream renamed an internal symbol the glue depends on,
# the build fails here.
set -e
cd "$(dirname "$0")"

REPO="${SLIRPNETSTACK_REPO:-https://github.com/KusakabeShi/slirpnetstack}"

if [ ! -d slirpnetstack/.git ]; then
    git clone "$REPO" slirpnetstack
else
    git -C slirpnetstack reset --hard
    git -C slirpnetstack pull --ff-only || echo "[!] git pull failed, continuing with local checkout" >&2
fi

sed -i 's/^package main$/package slirpnetstack/' slirpnetstack/*.go

cp _overlay/*.go slirpnetstack/

go build ./...
echo "[+] slirpnetstack synced and converted to library"
