#!/bin/bash
# Run the full integration suite. Individual tests skip themselves when
# their prerequisites are missing (root, /dev/vsock, debian image...).
set -u
cd "$(dirname "$0")"

TESTS=(
    "./test_tap.sh"
    "./test_afxdp.sh"
    "./test_vsock.sh"
    "./test_qemu.sh"                  # stream (default)
    "TRANSPORT=dgram ./test_qemu.sh"
    "TRANSPORT=tcp ./test_qemu.sh"
    "TRANSPORT=vhost-user ./test_qemu.sh"
)

pass=0 failcnt=0 failed=()
for t in "${TESTS[@]}"; do
    echo
    echo "===== $t ====="
    if bash -c "$t" 2>&1; then
        pass=$((pass + 1))
    else
        failcnt=$((failcnt + 1))
        failed+=("$t")
    fi
done

echo
echo "===== summary: $pass ok, $failcnt failed ====="
if [ "$failcnt" -gt 0 ]; then
    printf 'failed: %s\n' "${failed[@]}"
    exit 1
fi
