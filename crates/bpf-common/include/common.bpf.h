#pragma once

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define LOG_LEVEL_NONE 0
#define LOG_LEVEL_ERROR 1
#define LOG_LEVEL_DEBUG 2
const volatile int log_level = 0;

// NOTE: bpf_printk supports up to 3 arguments, while these LOG_ macros
// allow only up to 2 arguments since one is used by the probe name.
#define LOG_DEBUG(fmt, ...)                                                    \
  ({                                                                           \
    if (log_level >= LOG_LEVEL_DEBUG) {                                        \
      bpf_printk("[%s] " fmt, __func__, ##__VA_ARGS__);                        \
    }                                                                          \
  })

#define LOG_ERROR(fmt, ...)                                                    \
  ({                                                                           \
    if (log_level >= LOG_LEVEL_ERROR) {                                        \
      bpf_printk("[%s] " fmt " (ERROR)", __func__, ##__VA_ARGS__);             \
    }                                                                          \
  })

// ========================= POLICY TRACKING ==============================
// The following code contains the eBPF side of the Tracking Policy defined
// in ../modules/process_monitor/src/filtering_policy.rs
// See that module for more documentation.

// The bpf_map_def definition in libpf is compatible with aya, but it does not
// support pinning. This struct redefinition is compatibile with aya and is used
// by map_interest.
struct bpf_map_def_aya {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
  // aya extensions:
  unsigned int id;      // unused
  unsigned int pinning; // enables pinning
};

// map_interest tracks the policy for the given process.
// interest contains the process id (tgid) of processes whose events we sould
// ignore.
struct bpf_map_def_aya SEC("maps/map_interest") map_interest = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(char),
    .max_entries = 16384,
    .pinning = 1,
};

#define POLICY_INTERESTING 1
#define POLICY_CHILDREN_INTERESTING 2

// Return if we should generate events for this process.
// Takes a caller name which will be logged in case of error.
static __always_inline bool is_interesting(u32 tgid, const char *caller,
                                           bool do_warning) {
  u8 *value = (u8 *)bpf_map_lookup_elem(&map_interest, &tgid);
  // If we can't find an element, we process it
  if (value == NULL) {
    if (do_warning && log_level >= LOG_LEVEL_ERROR) {
      // We want to warn about missing entries in map_interest, but only
      // if process tracking is running. We check if map_interest contains
      // pid 1, which should always exist.
      u32 pid_init = 1;
      if (bpf_map_lookup_elem(&map_interest, &pid_init)) {
        LOG_ERROR("[%s] missing entry for pid %d", caller, tgid);
      }
    }
    return true;
  }
  bool target = *value & POLICY_INTERESTING;
  return target;
}

// Return tgid if we're interested in this process. Returns -1 if we're not.
#define interesting_tgid()                                                     \
  ({                                                                           \
    pid_t tgid = bpf_get_current_pid_tgid() >> 32;                             \
    if (!is_interesting(tgid, __func__, true))                                 \
      tgid = -1;                                                               \
    tgid;                                                                      \
  })

// Propagate interest about a child from the parent
static __always_inline void inherit_interest(u32 parent, u32 child) {
  u8 *ppolicy = (u8 *)bpf_map_lookup_elem(&map_interest, &parent);
  u8 policy = 0;
  if (ppolicy == NULL || (*ppolicy & POLICY_CHILDREN_INTERESTING)) {
    policy = POLICY_INTERESTING | POLICY_CHILDREN_INTERESTING;
  }
  long res = bpf_map_update_elem(&map_interest, &child, &policy, BPF_ANY);
  if (res != 0) {
    LOG_ERROR("error inheriting interest for %d (%d)", child, res);
  }
}

// Update interest for `tgid` to `interesting`.
// If with_children is not null, update the interest for child events too.
static __always_inline void update_interest(u32 tgid, bool interest,
                                            char *with_children) {
  u8 *p_policy = (u8 *)bpf_map_lookup_elem(&map_interest, &tgid);
  u8 policy;
  if (p_policy != NULL) {
    policy = *p_policy;
  } else {
    LOG_ERROR("policy for %d not found", tgid);
    policy = POLICY_INTERESTING | POLICY_CHILDREN_INTERESTING;
  }

  u8 change = POLICY_INTERESTING;
  // if the rule extends to children, set it accordingly
  if (with_children != NULL && *with_children != 0) {
    change |= POLICY_CHILDREN_INTERESTING;
  }

  if (interest) {
    // increase interest
    policy |= change;
  } else {
    // decrease interest
    policy &= ~change;
  }

  long res = bpf_map_update_elem(&map_interest, &tgid, &policy, BPF_ANY);
  if (res != 0) {
    LOG_ERROR("updating interest for %d (%d)", tgid, res);
  }
}

// To manually add a process to the map_interest:
// sudo bpftool map update pinned /sys/fs/bpf/pulsar/map_interest key 0x26 0xD1
// 0x01 0x00 value 1
//
// To get the key (pid) in little endian use:
// printf '%08x\n' $$ | fold -w2

// Detect if this eBPF call comes from a thread.
// It is a process if the thread id (pid) matches the process id (tgid)
// If out_tgid is not null, we save the tgid there.
static __always_inline int is_thread(pid_t *out_tgid) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  pid_t tgid = pid_tgid >> 32;
  pid_t pid = pid_tgid;
  if (out_tgid) {
    *out_tgid = tgid;
  }
  return pid != tgid;
}

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

#define PULSAR_LSM_HOOK(hook_point, args...)                                   \
  static __always_inline void on_##hook_point(void *ctx, TYPED_ARGS(args));    \
                                                                               \
  SEC("lsm/" #hook_point)                                                      \
  int BPF_PROG(hook_point, TYPED_ARGS(args), int ret) {                        \
    on_##hook_point(ctx, UNTYPED_ARGS(args));                                  \
    return ret;                                                                \
  }                                                                            \
                                                                               \
  SEC("kprobe/security_" #hook_point)                                          \
  int BPF_KPROBE(security_##hook_point, TYPED_ARGS(args)) {                    \
    on_##hook_point(ctx, UNTYPED_ARGS(args));                                  \
    return 0;                                                                  \
  }
