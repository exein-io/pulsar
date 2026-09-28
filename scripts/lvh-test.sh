#!/usr/bin/env bash
#
# Run the eBPF test-suite inside a VM booted from Cilium's prebuilt kernels,
# which is what the `lvh` CI job does. Expects `lvh`, `qemu` and `ssh` on PATH
# (see flake.nix).
#
#   scripts/lvh-test.sh <arch> <kernel-version> [test filter...]
#
#   arch:            amd64 | arm64
#   kernel-version:  e.g. 6.12-20250630.013259
#
# The repository is mounted inside the VM at /host, so the test-suite binary is
# run straight from ./target.

set -euo pipefail

ARCH="${1:?usage: lvh-test.sh <amd64|arm64> <kernel-version> [filter...]}"
KERNEL="${2:?usage: lvh-test.sh <amd64|arm64> <kernel-version> [filter...]}"
shift 2

REPO=$(cd "$(dirname "$0")/.." && pwd)
DATA="${LVH_DATA_DIR:-$REPO/target/lvh}"
PORT="${LVH_SSH_PORT:-2222}"
IMAGE_VERSION="${LVH_IMAGE_VERSION:-$KERNEL}"
PROFILE="${LVH_PROFILE:-release}"

case "$ARCH" in
    amd64)
        target=x86_64-unknown-linux-musl
        cpu_kind=host
        ;;
    arm64)
        target=aarch64-unknown-linux-musl
        # No KVM for a foreign architecture, so name a concrete CPU.
        cpu_kind=cortex-a57
        ;;
    *)
        echo "unsupported arch: $ARCH (expected amd64 or arm64)" >&2
        exit 1
        ;;
esac

SSH_OPTS=(-F /dev/null -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o ConnectTimeout=5 -p "$PORT")

cleanup() {
    ssh "${SSH_OPTS[@]}" root@localhost poweroff >/dev/null 2>&1 || true
    sleep 2
    [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> building test-suite for $target ($PROFILE)"
cargo build --target "$target" --profile "$PROFILE" --workspace --bin test-suite \
    --features all-vendored --features tls-rustls

binary="$REPO/target/$target/$PROFILE/test-suite"
[ -x "$binary" ] || { echo "missing $binary" >&2; exit 1; }

# find(1) exits 1 when the directory does not exist yet. Under `set -e` with
# `pipefail` that aborts the script before the pull that would create it, and
# `2>/dev/null` hides the reason. Probe through a helper that cannot fail.
find_one() {
    find "$1" -name "$2" -type f 2>/dev/null | head -1 || true
}

# Scope the rootfs cache by version, or a bare *.qcow2 probe reuses whatever
# image is already there and boots the kernel against the wrong userspace.
img_dir="$DATA/images/$ARCH/$IMAGE_VERSION"
mkdir -p "$img_dir" "$DATA/kernels/$ARCH"

echo "==> pulling rootfs kind:$IMAGE_VERSION ($ARCH)"
image=$(find_one "$img_dir" '*.qcow2')
if [ -z "$image" ]; then
    lvh images pull --platform "linux/$ARCH" --dir "$img_dir/" \
        "quay.io/lvh-images/kind:$IMAGE_VERSION"
    image=$(find_one "$img_dir" '*.qcow2')
    [ -n "$image" ] || { echo "no qcow2 under $img_dir after 'lvh images pull'" >&2
                         ls -R "$img_dir" >&2; exit 1; }
fi
echo "    image: $image"

echo "==> pulling kernel $KERNEL ($ARCH)"
vmlinuz=$(find_one "$DATA/kernels/$ARCH/$KERNEL" 'vmlinuz-*')
if [ -z "$vmlinuz" ]; then
    lvh kernels pull --platform="linux/$ARCH" --dir "$DATA/kernels/$ARCH" "$KERNEL"
    vmlinuz=$(find_one "$DATA/kernels/$ARCH/$KERNEL" 'vmlinuz-*')
    [ -n "$vmlinuz" ] || { echo "no vmlinuz under $DATA/kernels/$ARCH/$KERNEL after 'lvh kernels pull'" >&2
                           ls -R "$DATA/kernels/$ARCH" >&2; exit 1; }
fi
echo "    kernel: $vmlinuz"

echo "==> booting VM"
lvh run --host-mount="$REPO" --image "$image" --kernel "$vmlinuz" \
    --daemonize -p "$PORT:22" --cpu 4 --mem 4G --cpu-kind "$cpu_kind" \
    --qemu-arch "$ARCH" --console-log-file "$DATA/console-$ARCH-$KERNEL.log"

echo "==> waiting for ssh"
for i in $(seq 1 120); do
    if ssh "${SSH_OPTS[@]}" root@localhost true >/dev/null 2>&1; then
        echo "    ready after $((i * 3))s"
        break
    fi
    if [ "$i" -eq 120 ]; then
        echo "timed out waiting for ssh; console log:" >&2
        tail -50 "$DATA/console-$ARCH-$KERNEL.log" >&2 || true
        exit 1
    fi
    sleep 3
done

echo "==> running test-suite in VM"
ssh "${SSH_OPTS[@]}" root@localhost \
    "uname -a; /host/target/$target/$PROFILE/test-suite $*"
