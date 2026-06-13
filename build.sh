#!/bin/bash
# One-shot build. slirpnetstack is now a regular Go module dependency
# (pinned in go.mod), so the build is a plain `go build` — no checkout
# sync or package rename. The first build fetches the module; afterwards
# it comes from the Go module cache.
#
#   ./build.sh            host build            -> ./build/gvswitch
#   ./build.sh android    static linux/arm64    -> ./build/gvswitch-android-arm64
#   ./build.sh amd64      static linux/amd64    -> ./build/gvswitch-linux-amd64
#   ./build.sh all        all of the above
set -euo pipefail
cd "$(dirname "$0")"

target="${1:-host}"
case "$target" in
host)
    make build
    echo "[+] built ./build/gvswitch"
    ;;
android)
    make build-android
    ;;
amd64)
    make build-linux-amd64
    ;;
all)
    make build build-android build-linux-amd64
    echo "[+] built ./build/gvswitch"
    ;;
*)
    echo "usage: $0 [host|android|amd64|all]" >&2
    exit 2
    ;;
esac
