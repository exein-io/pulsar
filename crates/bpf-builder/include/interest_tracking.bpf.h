/* SPDX-License-Identifier: GPL-2.0-only */
#pragma once

#include "common.bpf.h"
#include "vmlinux.h"

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

// Map of containers to target
#define MAP_CONTAINER_RULES(map_container_rules)                               \
  struct {                                                                     \
    __uint(type, BPF_MAP_TYPE_HASH);                                           \
    __type(key, int);                                                          \
    __type(value, u8);                                                         \
    __uint(max_entries, 100);                                                  \
  } map_container_rules SEC(".maps");

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
  struct bpf_map_def_aya SEC("maps/" #map_interest) map_interest = {           \
      .type = BPF_MAP_TYPE_HASH,                                               \
      .key_size = sizeof(int),                                                 \
      .value_size = sizeof(char),                                              \
      .max_entries = 16384,                                                    \
      .pinning = pinning_enabled,                                              \
  };
// By default, all probes should use the global "m_interest" map,
// which is managed by process-monitor
#define GLOBAL_INTEREST_MAP m_interest
// Declare the global map
#define GLOBAL_INTEREST_MAP_DECLARATION                                        \
  MAP_INTEREST(GLOBAL_INTEREST_MAP, PINNING_ENABLED)

static __always_inline bool tracker_fork(struct bpf_map_def_aya *tracker,
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
static __always_inline bool tracker_check_rules(struct bpf_map_def_aya *tracker,
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
tracker_check_cgroup_rules(struct bpf_map_def_aya *tracker, void *rules,
                           struct task_struct *p, const char *cgroup_path) {
  char path[MAX_CGROUP_LEN];
  __builtin_memset(path, 0, MAX_CGROUP_LEN);
  bpf_core_read_str(path, MAX_CGROUP_LEN, cgroup_path);
  if (bpf_map_lookup_elem(rules, path)) {
    pid_t tgid = BPF_CORE_READ(p, tgid);
    u8 policy = INTEREST_TRACK_SELF | INTEREST_TRACK_CHILDREN;
    long res = bpf_map_update_elem(tracker, &tgid, &policy, BPF_ANY);
  }
}

/*
 * If the process is containerized, check whether the container_engine is
 * contained in the rules hashmap. If it is, insert the given process inside
 * the interest tracker
 */
static __always_inline void
tracker_check_container_rules(struct bpf_map_def_aya *tracker, void *rules,
                              struct task_struct *p, int container_engine) {
  int all_containers = 0;
  // If the process is containerized.
  if (container_engine > 0 &&
      // Look for a wildcard mark in container interest map.
      (bpf_map_lookup_elem(rules, &all_containers) ||
       // Or for the specific container engine.
       bpf_map_lookup_elem(rules, &container_engine))) {
    pid_t tgid = BPF_CORE_READ(p, tgid);
    u8 policy = INTEREST_TRACK_SELF | INTEREST_TRACK_CHILDREN;
    long res = bpf_map_update_elem(tracker, &tgid, &policy, BPF_ANY);
  }
}

// Returns true if an element was removed from the map.
// Does nothing if any process threat is still alive.
static __always_inline bool tracker_remove(struct bpf_map_def_aya *tracker,
                                           struct task_struct *p) {
  pid_t tgid = BPF_CORE_READ(p, group_leader, pid);
  // We want to ignore threads and focus on whole processes, so we have
  // to wait for the whole process group to exit. Unfortunately, checking
  // if the current task's pid matches its tgid is not enough because
  // the main thread could exit before the child one.
  if (BPF_CORE_READ(p, signal, live.counter) > 0) {
    return false;
  }
  // cleanup resources from tracker
  if (bpf_map_delete_elem(tracker, &tgid) != 0) {
    return false;
  }
  return true;
}

// Return tgid if we're interested in this process. Returns -1 if we're not.
#define tracker_interesting_tgid(tracker)                                      \
  ({                                                                           \
    pid_t tgid = bpf_get_current_pid_tgid() >> 32;                             \
    if (!tracker_is_interesting(tracker, tgid, __func__, true, true))          \
      tgid = -1;                                                               \
    tgid;                                                                      \
  })

// Return if we should generate events for this process.
// Takes a caller name which will be logged in case of error.
static __always_inline bool
tracker_is_interesting(struct bpf_map_def_aya *tracker, u32 tgid,
                       const char *caller, bool do_warning,
                       bool track_by_default) {
  u8 *value = (u8 *)bpf_map_lookup_elem(tracker, &tgid);
  // If we can't find an element, we process it
  if (value == NULL) {
    if (do_warning && log_level >= LOG_LEVEL_ERROR) {
      // We want to warn about missing entries in tracker, but only
      // if process tracking is running. We check if tracker contains
      // pid 1, which should always exist.
      u32 pid_init = 1;
      if (bpf_map_lookup_elem(tracker, &pid_init)) {
        LOG_ERROR("[%s] missing entry for pid %d", caller, tgid);
      }
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
