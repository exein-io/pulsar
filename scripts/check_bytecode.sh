#!/usr/bin/env sh

# Compile an eBPF source and print its bytecode. This is useful to understand
# verifier issues.

# Print commands
set -x
# Stop on error
set -e

# Compile eBPF to /tmp/obj.o, run from the repository root
${CLANG:-clang} -g -c "$1" -o /tmp/obj.o @compile_flags.txt
sleep 1
${LLVM_OBJDUMP:-llvm-objdump} -S --no-show-raw-insn /tmp/obj.o
