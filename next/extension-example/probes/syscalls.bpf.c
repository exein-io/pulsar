// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Counts the syscalls of every interesting process and writes the counts into
// the shared ring when the process exits. Modelled on pulsar-enterprise's
// anomaly-detection probe, which userspace polled instead.
#include "vmlinux.h"

#include "example/abi.h"
#include "pulsar/common.bpf.h"
#include "pulsar/interest_tracking.bpf.h"
#include "pulsar/ring.bpf.h"

char LICENSE[] SEC("license") = "GPL v2";

#define MAX_PROCESSES 1024

// Pinned by the process object, which keeps it up to date.
GLOBAL_INTEREST_MAP_DECLARATION;

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, pid_t);
  __type(value, struct example_syscall_activity);
  __uint(max_entries, MAX_PROCESSES);
} activities SEC(".maps");

// Never written: the first counts of a process, which don't fit on the stack.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, struct example_syscall_activity);
  __uint(max_entries, 1);
} empty_activity SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int BPF_PROG(sys_enter, struct pt_regs *regs, long id) {
  pid_t tgid = bpf_get_current_pid_tgid() >> 32;
  if (!tracker_is_interesting(&GLOBAL_INTEREST_MAP, tgid, __func__, false,
                              false))
    return 0;

  struct example_syscall_activity *activity =
      bpf_map_lookup_elem(&activities, &tgid);
  if (!activity) {
    u32 key = 0;
    struct example_syscall_activity *empty =
        bpf_map_lookup_elem(&empty_activity, &key);
    if (!empty)
      return 0;
    bpf_map_update_elem(&activities, &tgid, empty, BPF_NOEXIST);
    activity = bpf_map_lookup_elem(&activities, &tgid);
    if (!activity)
      return 0;
  }
  __sync_fetch_and_add(&activity->total, 1);
  if ((__u64)id < EXAMPLE_SYSCALLS_MAX)
    __sync_fetch_and_add(&activity->histogram[id], 1);
  return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int BPF_PROG(sched_process_exit, struct task_struct *p) {
  // Only when the last thread exits.
  if (BPF_CORE_READ(p, signal, live.counter) > 0)
    return 0;
  pid_t tgid = BPF_CORE_READ(p, tgid);
  struct example_syscall_activity *activity =
      bpf_map_lookup_elem(&activities, &tgid);
  if (!activity)
    return 0;

  struct example_syscall_activity_record *rec = PULSAR_RESERVE(
      struct example_syscall_activity_record, EXAMPLE_SYSCALL_ACTIVITY, p);
  if (!rec) {
    bpf_map_delete_elem(&activities, &tgid);
    return 0;
  }
  bpf_probe_read_kernel(&rec->body, sizeof(rec->body), activity);
  // Threads exiting together can all get here; only the one that removes the
  // counts writes them.
  if (bpf_map_delete_elem(&activities, &tgid) == 0)
    pulsar_submit(rec);
  else
    pulsar_discard(rec);
  return 0;
}
