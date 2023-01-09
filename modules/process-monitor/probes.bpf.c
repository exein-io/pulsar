// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "buffer.bpf.h"
#include "common.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define EVENT_FORK 0
#define EVENT_EXEC 1
#define EVENT_EXIT 2

struct fork_event {
  pid_t ppid;
};

struct exec_event {
  struct buffer_index filename;
  int argc;
  struct buffer_index argv;
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
  struct buffer buffer;
};

// used to send events to userspace
struct bpf_map_def_aya SEC("maps/events") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 0,
};

#define MAX_IMAGE_LEN 100

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, char[MAX_IMAGE_LEN]);
  __type(value, u8);
  __uint(max_entries, 100);
} target SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, char[MAX_IMAGE_LEN]);
  __type(value, u8);
  __uint(max_entries, 100);
} whitelist SEC(".maps");

// The BPF stack limit of 512 bytes is exceeded by process_event, so we use
// a per-cpu array as a workaround
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct process_event);
  __uint(max_entries, 1);
} eventmem SEC(".maps");

static __always_inline struct process_event *new_event() {
  u32 key = 0;
  struct process_event *event = bpf_map_lookup_elem(&eventmem, &key);
  if (!event) {
    LOG_ERROR("can't get event memory");
    return 0;
  }
  return event;
}

// This hook intercepts new process creations, inherits interest for the child
// from the parent and emits a fork event.
SEC("raw_tracepoint/sched_process_fork")
int BPF_PROG(process_fork, struct task_struct *parent,
             struct task_struct *child) {
  pid_t parent_tgid = BPF_CORE_READ(parent, tgid);
  pid_t child_tgid = BPF_CORE_READ(child, tgid);

  // if parent process group matches the child one, we're forking a thread
  // and we ignore the event.
  if (parent_tgid == child_tgid) {
    return 0;
  }
  // Propagate whitelist to child
  inherit_interest(parent_tgid, child_tgid);
  LOG_DEBUG("fork %d %d", parent_tgid, child_tgid);

  struct process_event *event = new_event();
  if (!event)
    return 0;
  event->event_type = EVENT_FORK;
  event->timestamp = bpf_ktime_get_ns();
  event->pid = child_tgid;
  event->fork.ppid = parent_tgid;

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct process_event));

  return 0;
}

SEC("raw_tracepoint/sched_process_exec")
int BPF_PROG(sched_process_exec, struct task_struct *p, pid_t old_pid,
             struct linux_binprm *bprm) {
  pid_t tgid = bpf_get_current_pid_tgid() >> 32;

  struct process_event *event = new_event();
  if (!event)
    return 0;
  event->event_type = EVENT_EXEC;
  event->timestamp = bpf_ktime_get_ns();
  event->pid = tgid;
  event->exec.argc = BPF_CORE_READ(bprm, argc);

  //  data_loc_filename is the offset from the beginning of the ctx structure
  //  of the executable filename
  const char *filename = BPF_CORE_READ(bprm, filename);
  buffer_index_init(&event->buffer, &event->exec.filename);
  buffer_append_str(&event->buffer, &event->exec.filename, filename,
                    BUFFER_MAX);

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct mm_struct *mm = BPF_CORE_READ(task, mm);
  long start = BPF_CORE_READ(mm, arg_start);
  long end = BPF_CORE_READ(mm, arg_end);
  int len = end - start;
  buffer_index_init(&event->buffer, &event->exec.argv);
  buffer_append_user_memory(&event->buffer, &event->exec.argv,
                            (const char *)start, len);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct process_event));

  char image[MAX_IMAGE_LEN];
  __builtin_memset(&image, 0, sizeof(image));
  bpf_core_read_str(&image, MAX_IMAGE_LEN, filename);

  // Check whitelist
  char *res = bpf_map_lookup_elem(&whitelist, image);
  if (res) {
    LOG_DEBUG("whitelisting %s", image);
    update_interest(tgid, false, res);
  }

  // Check target list
  res = bpf_map_lookup_elem(&target, image);
  if (res) {
    LOG_DEBUG("targeting %s", image);
    update_interest(tgid, true, res);
  }

  return 0;
}

#define PF_EXITING 4

// This is attached to tracepoint:sched:sched_process_exit
SEC("raw_tracepoint/sched_process_exit")
int BPF_PROG(sched_process_exit, struct task_struct *p) {
  pid_t tgid = BPF_CORE_READ(p, group_leader, pid);

  // We want to ignore threads and focus on whole processes, so we have
  // to wait for the whole process group to exit. Unfortunately, checking
  // if the current task's pid matches its tgid is not enough because
  // the main thread could exit before the child one.
  if (BPF_CORE_READ(p, signal, live.counter) > 0) {
    return 0;
  }

  // cleanup resources from map_interest
  if (bpf_map_delete_elem(&map_interest, &tgid) != 0) {
    LOG_DEBUG("%d not found in map_interest during exit", tgid);
    // Multiple threads may exit at the same time, causing the loop above
    // to pass multiple times. Since we want to generate only one event,
    // we'll consider a missing entry in map_interest as a signal that
    // we've already emitted the exit event.
    return 0;
  }

  struct process_event *event = new_event();
  if (!event)
    return 0;
  event->event_type = EVENT_EXIT;
  event->timestamp = bpf_ktime_get_ns();
  // The PID is the thread id of the progress group leader
  event->pid = tgid;
  // NOTE: here we're assuming the exit code is set by the last exiting thread
  event->exit.exit_code = BPF_CORE_READ(p, exit_code) >> 8;

  LOG_DEBUG("exitited at %ld with code %d", event->timestamp,
            event->exit.exit_code);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct process_event));
  return 0;
}
