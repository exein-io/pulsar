/* SPDX-License-Identifier: GPL-2.0-only */
#pragma once

#include "bpf/bpf_helpers.h"
#include "common.bpf.h"
#include "task.bpf.h"
#include "vmlinux.h"

// This header-only library allows to apply eBPF tracing hooks only to some
// processes.
// See ./filtering_example.bpf.c for example usage (it's compiled as part of the
// test suite)

#define MAX_IMAGE_LEN 100
#define MAX_CGROUP_LEN 300

// Define a map containing the rules for deciding what is of interest.
// > map_rules["/usr/bin/process"] = <RULE BITMAP>
// RULE_EXTENDS RULE_INTEREST Description
// 0            1             Track the given process
// 1            1             Track the given process and its children
// 0            0             Don't track the given process
// 1            0             Don't track the given process and its children
#define RULE_INTEREST 1
#define RULE_EXTENDS 2
#define MAP_RULES(map_rules)                                                   \
  struct {                                                                     \
    __uint(type, BPF_MAP_TYPE_HASH);                                           \
    __type(key, char[MAX_IMAGE_LEN]);                                          \
    __type(value, u8);                                                         \
    __uint(max_entries, 100);                                                  \
  } map_rules SEC(".maps");

// Map of cgroups to target
#define MAP_CGROUP_RULES(map_cgroup_rules)                                     \
  struct {                                                                     \
    __uint(type, BPF_MAP_TYPE_HASH);                                           \
    __type(key, char[MAX_CGROUP_LEN]);                                         \
    __type(value, u8);                                                         \
    __uint(max_entries, 100);                                                  \
  } map_cgroup_rules SEC(".maps");

// Define a map containing the interest for each process on the system.
// > map_interest[<process pid>] = <INTEREST BITMAP>
// TRACK_CHILDREN TRACK_SELF Description
// 0              1          Track the given process, but not its children
// 1              1          Track the given process and its children
// 0              0          Don't track the given process and its children
// 1              0          Track only the children, not the process itself
#define INTEREST_TRACK_SELF 1
#define INTEREST_TRACK_CHILDREN 2
#define PINNING_ENABLED 1
#define PINNING_DISABLED 0
#define MAP_INTEREST(map_interest, pinning_enabled)                            \
  struct {                                                                     \
      __uint(type, BPF_MAP_TYPE_TASK_STORAGE);                                 \
      __uint(map_flags, BPF_F_NO_PREALLOC);                                    \
      __type(key, int);                                                        \
      __type(value, u8);                                                       \
  } map_interest SEC(".maps");
// By default, all probes should use the global "m_interest" map,
// which is managed by process-monitor
#define GLOBAL_INTEREST_MAP m_interest
// Declare the global map
#define GLOBAL_INTEREST_MAP_DECLARATION                                        \
  MAP_INTEREST(GLOBAL_INTEREST_MAP, PINNING_ENABLED)

static __always_inline bool tracker_fork(void *tracker,
                                         struct task_struct *parent,
                                         struct task_struct *child) {
  pid_t parent_tgid = BPF_CORE_READ(parent, tgid);
  pid_t child_tgid = BPF_CORE_READ(child, tgid);

  // if parent process group matches the child one, we're forking a thread
  // and we ignore the event.
  if (parent_tgid == child_tgid) {
    return 0;
  }

  // Propagate interest about a child from the parent
  u8 *ppolicy = (u8 *)bpf_map_lookup_elem(tracker, &parent_tgid);
  u8 policy = 0;
  if (ppolicy == NULL || (*ppolicy & INTEREST_TRACK_CHILDREN)) {
    policy = INTEREST_TRACK_SELF | INTEREST_TRACK_CHILDREN;
  }
  long res = bpf_map_update_elem(tracker, &child_tgid, &policy, BPF_ANY);
  if (res != 0) {
    LOG_ERROR("error inheriting interest for %d (%d)", child, res);
  }
  return 1;
}

// Check if the new process filename should result in tracker changes
static __always_inline bool tracker_check_rules(void *tracker,
                                                void *rules,
                                                struct task_struct *p,
                                                const char *filename) {
  pid_t tgid = BPF_CORE_READ(p, group_leader, pid);
  char image[MAX_IMAGE_LEN];
  __builtin_memset(&image, 0, sizeof(image));
  bpf_core_read_str(&image, MAX_IMAGE_LEN, filename);

  // Check if a rule applies
  char *rule = bpf_map_lookup_elem(rules, image);
  if (!rule) {
    return 0;
  }

  // Get current policy
  u8 *p_policy = (u8 *)bpf_map_lookup_elem(tracker, &tgid);
  u8 policy;
  if (p_policy != NULL) {
    policy = *p_policy;
  } else {
    LOG_ERROR("policy for %d not found", tgid);
    policy = INTEREST_TRACK_SELF | INTEREST_TRACK_CHILDREN;
  }

  // Update policy for current process
  u8 change = INTEREST_TRACK_SELF;
  // if the rule extends to children, set it accordingly
  // here it's used differently
  if (*rule & RULE_EXTENDS) {
    change |= INTEREST_TRACK_CHILDREN;
  }

  if (*rule & RULE_INTEREST) {
    // increase interest
    policy |= change;
  } else {
    // decrease interest
    policy &= ~change;
  }

  long res = bpf_map_update_elem(tracker, &tgid, &policy, BPF_ANY);
  if (res != 0) {
    LOG_ERROR("updating interest for %d (%d)", tgid, res);
  }
  return 0;
}

// Check if the cgroup_path is contained in the rules hashmap. If it is,
// insert the given process inside the interest tracker.
static __always_inline void
tracker_check_cgroup_rules(void *tracker, void *rules,
                           struct task_struct *p, const char *cgroup_path) {
  char path[MAX_CGROUP_LEN];
  __builtin_memset(path, 0, MAX_CGROUP_LEN);
  bpf_core_read_str(path, MAX_CGROUP_LEN, cgroup_path);
  if (bpf_map_lookup_elem(rules, path)) {
    u8 policy = INTEREST_TRACK_SELF | INTEREST_TRACK_CHILDREN;
    u8 *value = (u8 *)bpf_task_storage_get(tracker, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (value)
      *value = policy;
  }
}

// Return tgid if we're interested in this process. Returns -1 if we're not.
#define tracker_interesting_tgid(tracker)                                      \
  ({                                                                           \
    struct task_struct *p = get_current_task();                                \
    pid_t tgid = BPF_CORE_READ(p, tgid);                                       \
    if (!tracker_is_interesting(tracker, p, __func__, true, true))             \
      tgid = -1;                                                               \
    tgid;                                                                      \
  })

// Return if we should generate events for this process.
// Takes a caller name which will be logged in case of error.
static __always_inline bool
tracker_is_interesting(void *tracker, struct task_struct *p,
                       const char *caller, bool do_warning,
                       bool track_by_default) {
  u8 *value = (u8 *)bpf_task_storage_get(tracker, p, 0, 0);
  // If we can't find an element, we process it
  if (value == NULL) {
    if (do_warning && log_level >= LOG_LEVEL_ERROR) {
      // We want to warn about missing entries in tracker, but only
      // if process tracking is running. We check if tracker contains
      // // pid 1, which should always exist.
      // u32 pid_init = 1;
      // if (bpf_map_lookup_elem(tracker, &pid_init)) {
      pid_t tgid = BPF_CORE_READ(p, tgid);
      LOG_ERROR("[%s] missing entry for pid %d", caller, tgid);
      // }
    }
    return track_by_default;
  }
  bool target = *value & INTEREST_TRACK_SELF;
  return target;
}

// Debugging tips
// --------------
//
// To manually add a process to the map_interest:
// sudo bpftool map update pinned /sys/fs/bpf/pulsar/map_interest key 0x26 0xD1
// 0x01 0x00 value 1
//
// To get the key (pid) in little endian use:
// printf '%08x\n' $$ | fold -w2
