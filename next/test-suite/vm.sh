#!/usr/bin/env bash
# Runs test-suite-next in QEMU, as the init of an initramfs. Needs access to
# /dev/kvm, not root: inside the VM the suite runs as root.
#
#   next/test-suite/vm.sh <kernel image> [test-suite-next arguments]
#
# The kernel needs BTF and BPF LSM. Kernel parameters with a `=`, such as
# RUST_LOG=debug, can be added with KERNEL_ARGS.
set -euo pipefail

kernel=$1
shift
target=x86_64-unknown-linux-musl
root=$(cd "$(dirname "$0")/../.." && pwd)

cargo build --quiet --manifest-path "$root/Cargo.toml" -p next-test-suite --target "$target"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/initramfs"
cp "$root/target/$target/debug/test-suite-next" "$work/initramfs/"
(cd "$work/initramfs" && echo test-suite-next | cpio --quiet -o -H newc) | gzip -1 >"$work/initramfs.gz"

qemu-system-x86_64 -enable-kvm -cpu host -m 1G -smp 2 -nographic -no-reboot \
    -kernel "$kernel" -initrd "$work/initramfs.gz" \
    -append "console=ttyS0 quiet panic=-1 rdinit=/test-suite-next ${KERNEL_ARGS:-} -- $*" |
    tee "$work/console"

code=$(tr -d '\r' <"$work/console" | sed -n 's/^test-suite-next exit code: \([0-9]*\)$/\1/p')
exit "${code:-1}"
