#!/usr/bin/env sh

# Compile an eBPF source and print its bytecode. This is useful to understand
# verifier issues.

# Print commands
set -x
# Stop on error
set -e

# Compile eBPF to /tmp/obj.o
clang -g -O2 -c $1 -o /tmp/obj.o -target bpf -D__TARGET_ARCH_x86 -I crates/bpf-builder/include/ -I crates/bpf-builder/include/x86_64/
sleep 1
llvm-objdump -S --no-show-raw-insn /tmp/obj.o
