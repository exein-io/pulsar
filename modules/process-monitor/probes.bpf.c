// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "common.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define NAME_MAX 264
#define EVENT_FORK 0
#define EVENT_EXEC 1
#define EVENT_EXIT 2

struct fork_event {
  pid_t ppid;
};

struct exec_event {
  char filename[NAME_MAX];
};

struct exit_event {
  u32 exit_code;
};

struct process_event {
  u64 timestamp;
  pid_t pid;
  u32 event_type;
  union {
    struct fork_event fork;
    struct exec_event exec;
    struct exit_event exit;
  };
};

// used to send events to userspace
struct bpf_map_def SEC("maps/events") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 0,
};

#define MAX_IMAGE_LEN 100

struct bpf_map_def SEC("maps/target") target = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = MAX_IMAGE_LEN,
    .value_size = sizeof(u8),
    .max_entries = 100,
};

struct bpf_map_def SEC("maps/whitelist") whitelist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = MAX_IMAGE_LEN,
    .value_size = sizeof(u8),
    .max_entries = 100,
};

// This hook intercepts new process creations, inherits interest for the child
// from the parent and emits a fork event.
// The sched_process_fork tracepoint would have been better, sadly we would be
// given only the pid of the child and we need its tgid in order to detect
// threads. We track the wake_up_new_task in order to have the child task_struct
// which is passed as the first argument.
// This is clearly less reliable than the tracepoint, so we may have to
// conditially revert to it if kernels don't support this kproble. The problem
// with that is that we would fill map_interest with useless thread entries.
SEC("kprobe/wake_up_new_task")
int wake_up_new_task(struct pt_regs *ctx) {
  pid_t parent_tgid = bpf_get_current_pid_tgid() >> 32;
  struct task_struct *child = (struct task_struct *)PT_REGS_PARM1(ctx);
  if (!child) {
    bpf_printk("wake_up_new_task: error getting child task");
  }
  pid_t child_tgid = BPF_CORE_READ(child, tgid);
  // if parent process group matches the child one, we're forking a thread
  // and we ignore the event.
  if (parent_tgid == child_tgid) {
    // pid_t child_pid = BPF_CORE_READ(child, pid);
    // bpf_printk("ignoring thread %d %d", child_tgid, child_pid);
    return 0;
  }
  // Propagate whitelist to child
  inherit_interest(parent_tgid, child_tgid);
  // bpf_printk("fork %d %d", parent_tgid, child_tgid);

  struct process_event event = {};
  event.event_type = EVENT_FORK;
  event.timestamp = bpf_ktime_get_ns();
  event.pid = child_tgid;
  event.fork.ppid = parent_tgid;

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                        sizeof(struct process_event));

  return 0;
}

// This is attached to tracepoint:sched:sched_process_exec, with input:
// struct trace_event_raw_sched_process_exec {
//         struct trace_entry ent;
//         u32 __data_loc_filename;
//         pid_t pid;
//         pid_t old_pid;
//         char __data[0];
// };
SEC("tracepoint/sched_process_exec")
int sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
  pid_t tgid = bpf_get_current_pid_tgid() >> 32;

  struct process_event event = {};
  event.event_type = EVENT_EXEC;
  event.timestamp = bpf_ktime_get_ns();
  event.pid = tgid;

  //  data_loc_filename is the offset from the beginning of the ctx structure
  //  of the executable filename
  u16 off = ctx->__data_loc_filename & 0xFFFF;
  bpf_core_read_str(&event.exec.filename, NAME_MAX, (char *)ctx + off);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                        sizeof(struct process_event));

  char image[MAX_IMAGE_LEN];
  __builtin_memset(&image, 0, sizeof(image));
  bpf_core_read_str(&image, MAX_IMAGE_LEN, (char *)ctx + off);

  // Check whitelist
  char *res = bpf_map_lookup_elem(&whitelist, image);
  if (res) {
    bpf_printk("whitelisting %s", image);
    update_interest(tgid, false, res);
  }

  // Check target list
  res = bpf_map_lookup_elem(&target, image);
  if (res) {
    bpf_printk("targeting %s", image);
    update_interest(tgid, true, res);
  }

  return 0;
}

// This is attached to tracepoint:sched:sched_process_exit
SEC("tracepoint/sched_process_exit")
int sched_process_exit(void *ctx) {
  pid_t tgid;
  // If the thread id (pid) is different from the process id (tgid)
  // a thread exited and we ignore the event.
  if (is_thread(&tgid))
    return 0;

  // cleanup resources from map_interest
  if (bpf_map_delete_elem(&map_interest, &tgid) != 0) {
    bpf_printk("%d not found in map_interest during exit", tgid);
  }

  struct process_event event = {};
  event.event_type = EVENT_EXIT;
  event.timestamp = bpf_ktime_get_ns();
  event.pid = tgid;

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  event.exit.exit_code = BPF_CORE_READ(task, exit_code) >> 8;

  bpf_printk("exit %d -> %d at %ld", tgid, event.exit.exit_code,
             event.timestamp);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                        sizeof(struct process_event));
  return 0;
}
