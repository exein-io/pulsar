# Development and CI tasks. Everything here expects the nix devShell
# (`nix develop`, or `direnv allow`) to be active.

set shell := ["bash", "-euo", "pipefail", "-c"]

# Targets of the CI build/lint/test matrix.
targets := "x86_64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-gnu aarch64-unknown-linux-musl riscv64gc-unknown-linux-gnu riscv64gc-unknown-linux-musl"

host_target := "x86_64-unknown-linux-gnu"

# Kernels the integration jobs run against.
lvh_build_date := "20250630.013259"
lvh_kernels := "5.15 6.1 6.6 6.12"
architest_kernels_amd64 := "5.13,5.15,6.0,6.3,6.6"
architest_kernels_arm64 := "5.15,6.2,6.6"

_default:
    @just --list

# musl needs vendored openssl/sqlite; gnu links the system ones.
_features target:
    @case "{{target}}" in \
        *musl) echo "--no-default-features --features full --features all-vendored --features tls-rustls" ;; \
        *)     echo "--features full" ;; \
    esac

# ---------------------------------------------------------------- build/lint

# Build one target (default: host).
build target=host_target profile="dev":
    #!/usr/bin/env bash
    set -euo pipefail
    args=$(just _features {{target}})
    extra=""; [ "{{profile}}" = "release" ] && extra="--release"
    cargo build --locked --target={{target}} --workspace --all-targets $args $extra

# Build every target.
build-all profile="dev":
    #!/usr/bin/env bash
    set -euo pipefail
    for t in {{targets}}; do echo "=== build $t ({{profile}}) ==="; just build "$t" {{profile}}; done

# Clippy one target (default: host).
clippy target=host_target:
    #!/usr/bin/env bash
    set -euo pipefail
    args=$(just _features {{target}})
    cargo clippy --locked --target={{target}} --workspace --all-targets $args -- -D warnings

# Clippy every target.
clippy-all:
    #!/usr/bin/env bash
    set -euo pipefail
    for t in {{targets}}; do echo "=== clippy $t ==="; just clippy "$t"; done

fmt:
    cargo fmt

fmt-check:
    cargo fmt -- --check

# ---------------------------------------------------------------- unit tests

# Unit tests for one target (foreign architectures run under qemu-user).
test target=host_target:
    #!/usr/bin/env bash
    set -euo pipefail
    args=$(just _features {{target}})
    cargo test --locked --target={{target}} --workspace --all-targets $args

# Unit tests for every target.
test-all:
    #!/usr/bin/env bash
    set -euo pipefail
    for t in {{targets}}; do echo "=== test $t ==="; just test "$t"; done

# --------------------------------------------------------- integration tests

# eBPF suite in a full-system QEMU VM (buildroot images); kernels default to CI's list.
architest arch="amd64" kernels="":
    #!/usr/bin/env bash
    # just architest amd64        -> all CI kernels for that arch
    # just architest amd64 6.6    -> one kernel
    set -euo pipefail
    case "{{arch}}" in
        amd64) target=x86_64-unknown-linux-musl;  default_kernels="{{architest_kernels_amd64}}" ;;
        arm64) target=aarch64-unknown-linux-musl; default_kernels="{{architest_kernels_arm64}}" ;;
        *) echo "unsupported arch: {{arch}} (amd64|arm64)" >&2; exit 1 ;;
    esac
    kernels="{{kernels}}"; [ -z "$kernels" ] && kernels="$default_kernels"
    cargo xtask test-suite --force-architest --target "$target" --kernel-versions "$kernels"

# architest on both architectures.
architest-all:
    #!/usr/bin/env bash
    set -euo pipefail
    for a in amd64 arm64; do echo "=== architest $a ==="; just architest "$a"; done

# eBPF suite on Cilium's prebuilt kernels (KVM on amd64); kernels default to CI's list.
lvh arch="amd64" kernel="":
    #!/usr/bin/env bash
    # just lvh amd64        -> all CI kernels for that arch
    # just lvh amd64 6.12   -> one kernel
    set -euo pipefail
    kernels="{{kernel}}"; [ -z "$kernels" ] && kernels="{{lvh_kernels}}"
    for k in $kernels; do
        echo "=== lvh {{arch}} kernel $k ==="
        ./scripts/lvh-test.sh "{{arch}}" "$k-{{lvh_build_date}}"
    done

# lvh on both architectures.
lvh-all:
    #!/usr/bin/env bash
    set -euo pipefail
    for a in amd64 arm64; do echo "=== lvh $a ==="; just lvh "$a"; done

# Every integration test.
integration: architest-all lvh-all

# ---------------------------------------------------------------- aggregates

# The unit half of CI: formatting, lint, build and unit tests for all targets.
ci: fmt-check clippy-all build-all test-all

# Everything, including the VM-based integration tests.
all: ci integration

# ------------------------------------------------------------------- release

# Release binaries for a target, normalised for distribution.
dist target:
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{target}}" in
        *musl) args="--no-default-features --features full --features all-vendored --features tls-rustls" ;;
        *)     args="--features full --features openssl-vendored" ;;
    esac
    cargo build --locked --target={{target}} --release --bin pulsard --bin pulsar $args
    case "{{target}}" in
        *musl) exit 0 ;;                       # static, nothing to normalise
        x86_64*)    interp=/lib64/ld-linux-x86-64.so.2 ;;
        aarch64*)   interp=/lib/ld-linux-aarch64.so.1 ;;
        riscv64gc*) interp=/lib/ld-linux-riscv64-lp64d.so.1 ;;
    esac
    # A nix toolchain links against its own glibc and records store paths, which
    # do not exist on the target system. Point the binary back at the
    # conventional loader and soname, and drop the store RPATH.
    for bin in pulsard pulsar; do
        f="target/{{target}}/release/$bin"
        patchelf --set-interpreter "$interp" --remove-rpath "$f"
        patchelf --replace-needed libsqlite3.so libsqlite3.so.0 "$f" 2>/dev/null || true
        echo "$bin: $(readelf -l "$f" | awk '/interpreter/{print $NF}' | tr -d '[]')"
    done

# ---------------------------------------------------------------------- misc

# compile_commands.json for clangd on the .bpf.c sources.
compile-commands:
    ./scripts/gen_compile_commands.sh

clean:
    cargo clean
