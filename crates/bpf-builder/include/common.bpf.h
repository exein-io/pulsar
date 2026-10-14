/* SPDX-License-Identifier: GPL-2.0-only */
#pragma once

#include "vmlinux.h"

#include "bpf/bpf_core_read.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"

#include "aya_log.bpf.h"

const volatile int LINUX_KERNEL_VERSION;

// --------------- PULSAR_LSM_HOOK MACRO DEFINITION --------------
// This macro makes it easy to hook into LSM attach points, keeping a kprobe
// fallback.
// PULSAR_LSM_HOOK(hook_point, args) will attach to `lsm/<hook_point>` and
// `kprobe/security_<hook_point>`. It calls function `on_<hook_point>`, which
// must be defined by the user and accept the specified args args.
//
// Example:
// PULSAR_LSM_HOOK(file_open, struct file *, file);
//
// Expands to:
//
// SEC("lsm/file_open")
// int BPF_PROG(file_open, struct file *file, int ret) {
//   on_file_open(ctx, file);
//   return ret;
// }
//
// SEC("kprobe/security_file_open")
// int BPF_KPROBE(security_file_open, struct file *file) {
//   on_file_open(ctx, file);
//   return 0;
// }

#define TYPED_ARGS_2(a, b) a b
#define TYPED_ARGS_4(a, b, args...) a b, TYPED_ARGS_2(args)
#define TYPED_ARGS_6(a, b, args...) a b, TYPED_ARGS_4(args)
#define TYPED_ARGS_8(a, b, args...) a b, TYPED_ARGS_6(args)
#define TYPED_ARGS_10(a, b, args...) a b, TYPED_ARGS_8(args)
#define TYPED_ARGS(args...) ___bpf_apply(TYPED_ARGS_, ___bpf_narg(args))(args)

#define UNTYPED_ARGS_2(a, b) b
#define UNTYPED_ARGS_4(a, b, args...) b, UNTYPED_ARGS_2(args)
#define UNTYPED_ARGS_6(a, b, args...) b, UNTYPED_ARGS_4(args)
#define UNTYPED_ARGS_8(a, b, args...) b, UNTYPED_ARGS_6(args)
#define UNTYPED_ARGS_10(a, b, args...) b, UNTYPED_ARGS_8(args)
#define UNTYPED_ARGS(args...)                                                  \
  ___bpf_apply(UNTYPED_ARGS_, ___bpf_narg(args))(args)

#ifdef FEATURE_LSM
#define PULSAR_LSM_HOOK(hook_point, args...)                                   \
  static __always_inline void on_##hook_point(void *ctx, TYPED_ARGS(args));    \
                                                                               \
  SEC("lsm/" #hook_point)                                                      \
  int BPF_PROG(hook_point, TYPED_ARGS(args), int ret) {                        \
    on_##hook_point(ctx, UNTYPED_ARGS(args));                                  \
    return ret;                                                                \
  }
#else
#define PULSAR_LSM_HOOK(hook_point, args...)                                   \
  static __always_inline void on_##hook_point(void *ctx, TYPED_ARGS(args));    \
                                                                               \
  SEC("kprobe/security_" #hook_point)                                          \
  int BPF_KPROBE(security_##hook_point, TYPED_ARGS(args)) {                    \
    on_##hook_point(ctx, UNTYPED_ARGS(args));                                  \
    return 0;                                                                  \
  }
#endif
