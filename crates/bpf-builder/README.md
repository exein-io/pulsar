# BPF builder

This crate is responsible for compiling our eBPF programs.

## Editor setup

The root [`compile_flags.txt`](../../compile_flags.txt) lets clangd-based
editors understand the eBPF sources without any setup. It mirrors the flags
passed to clang in [`src/lib.rs`](src/lib.rs), so keep the two in sync. It
targets x86_64 with all optional eBPF features enabled.

To work with another architecture, override the flags in your clangd user
config (`~/.config/clangd/config.yaml`), for example for aarch64:

```yaml
CompileFlags:
  Remove: [-D__TARGET_ARCH_*, -Icrates/bpf-builder/vmlinux/*]
  Add: [-D__TARGET_ARCH_arm64, -Icrates/bpf-builder/vmlinux/aarch64]
```

For riscv64 use `-D__TARGET_ARCH_riscv` and `vmlinux/riscv64`.

A `compile_commands.json` takes precedence over `compile_flags.txt`, so delete
any left over from the removed `scripts/gen_compile_commands.sh`.
