#!/usr/bin/env sh

# Build a compile_commands.json, which is useful for auto-completion engines.
#
# Flags must mirror `crates/bpf-builder/src/lib.rs`. `-target bpf` in particular
# is required: without it clang does not know the CO-RE builtins the probes use.

set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
include="${root}/crates/bpf-builder/include"
clang="${CLANG:-clang}"

case "$(uname -m)" in
    x86_64)          arch=x86_64  ; target_arch=x86   ;;
    aarch64 | arm64) arch=aarch64 ; target_arch=arm64 ;;
    riscv64)         arch=riscv64 ; target_arch=riscv ;;
    arm*)            arch=arm     ; target_arch=arm   ;;
    *)
        echo "unsupported host architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

out="${root}/compile_commands.json"

{
    printf '[\n'
    first=1
    find "${root}/crates" -name '*.bpf.c' | sort | while read -r source; do
        if [ "${first}" -eq 1 ]; then
            first=0
        else
            printf ',\n'
        fi
        printf '  {\n'
        printf '    "directory": "%s",\n' "${root}"
        printf '    "file": "%s",\n' "${source}"
        printf '    "arguments": [\n'
        printf '      "%s",\n' "${clang}"
        printf '      "-target", "bpf",\n'
        printf '      "-I%s",\n' "${include}"
        printf '      "-I%s/%s",\n' "${include}" "${arch}"
        printf '      "-g",\n'
        printf '      "-O2",\n'
        printf '      "-D__TARGET_ARCH_%s",\n' "${target_arch}"
        printf '      "-fno-stack-protector",\n'
        printf '      "-c", "%s",\n' "${source}"
        printf '      "-o", "/dev/null"\n'
        printf '    ]\n'
        printf '  }'
    done
    printf '\n]\n'
} > "${out}"

echo "wrote ${out} ($(grep -c '"file"' "${out}") entries)"
