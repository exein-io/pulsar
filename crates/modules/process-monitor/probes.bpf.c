// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "buffer.bpf.h"
#include "common.bpf.h"
#include "get_path.bpf.h"
#include "output.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define EVENT_FORK 0
#define EVENT_EXEC 1
#define EVENT_EXIT 2
#define EVENT_CHANGE_PARENT 3
#define EVENT_CGROUP_MKDIR 4

#define MAX_IMAGE_LEN 100
#define MAX_ORPHANS 30

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

struct change_parent_event {
  pid_t ppid;
};

struct cgroup_mkdir_event {
  struct buffer_index path;
  u64 id;
};

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

OUTPUT_MAP(events, process_event, {
  struct fork_event fork;
  struct exec_event exec;
  struct exit_event exit;
  struct change_parent_event change_parent;
  struct cgroup_mkdir_event cgroup_mkdir;
});

struct pending_dead_process {
  // Pid of the dead process who left orphans
  pid_t dead_parent;
  // Timestamp of the death of parent
  u64 timestamp;
  // List of orphans which will be re-parented
  struct task_struct *orphans[MAX_ORPHANS];
};

// Temporary map used to communicate the list of orphaned processes from
// `sched_process_exit` to `sched_switch`. There we'll be able to read
// the new parent of the orphans and emit an EVENT_CHANGE_PARENT.
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct pending_dead_process);
  __uint(max_entries, 1);
} orphans_map SEC(".maps");

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

  struct process_event *event = output_temp();
  if (!event)
    return 0;
  event->event_type = EVENT_FORK;
  event->buffer.len = 0;
  event->timestamp = bpf_ktime_get_ns();
  event->pid = child_tgid;
  event->fork.ppid = parent_tgid;

  output_event(ctx, &events, event, sizeof(struct process_event),
               event->buffer.len);

  return 0;
}

SEC("raw_tracepoint/sched_process_exec")
int BPF_PROG(sched_process_exec, struct task_struct *p, pid_t old_pid,
             struct linux_binprm *bprm) {
  pid_t tgid = bpf_get_current_pid_tgid() >> 32;

  struct process_event *event = output_temp();
  if (!event)
    return 0;
  event->event_type = EVENT_EXEC;
  event->buffer.len = 0;
  event->timestamp = bpf_ktime_get_ns();
  event->pid = tgid;
  event->exec.argc = BPF_CORE_READ(bprm, argc);
  // This is needed because the first MAX_IMAGE_LEN bytes of buffer will
  // be used as a lookup key for the target and whitelist maps and garbage
  // would make the search fail.
  __builtin_memset((char *)&event->buffer.buffer, 0, MAX_IMAGE_LEN);

  // We want to get the absolute path of the executable we're running.
  // When executing a process with a relative path, bprm->filename won't be
  // enough and we'll have to do a full path traversal. When starts with /
  // though, we can just copy it, as an optimization.
  const char *bprm_filename = BPF_CORE_READ(bprm, filename);
  char first_character = 0;
  bpf_core_read(&first_character, 1, bprm_filename);
  if (first_character == '/') {
    buffer_index_init(&event->buffer, &event->exec.filename);
    buffer_append_str(&event->buffer, &event->exec.filename, bprm_filename,
                      BUFFER_MAX);
  } else {
    struct path path = BPF_CORE_READ(bprm, file, f_path);
    get_path_str(&path, &event->buffer, &event->exec.filename);
  }

  char *image = (char *)&event->buffer.buffer;

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

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct mm_struct *mm = BPF_CORE_READ(task, mm);
  long start = BPF_CORE_READ(mm, arg_start);
  long end = BPF_CORE_READ(mm, arg_end);
  int len = end - start;
  buffer_index_init(&event->buffer, &event->exec.argv);
  buffer_append_user_memory(&event->buffer, &event->exec.argv, (void *)start,
                            len);

  output_event(ctx, &events, event, sizeof(struct process_event),
               event->buffer.len);

  return 0;
}

// When a process exits, we have to add all its children to orphans_map. This
// will be checked as soon as possibile (the scheduler iteration which happens
// immediately after an exit syscall) for changes to a process parent.
static __always_inline void collect_orphans(pid_t tgid, struct task_struct *p) {
  u32 key = 0;
  struct pending_dead_process *pending =
      bpf_map_lookup_elem(&orphans_map, &key);
  if (!pending) {
    return;
  }
  pending->dead_parent = tgid;
  pending->timestamp = bpf_ktime_get_ns();
  // Collect orphans by iterating the dead process children
  struct list_head *next = BPF_CORE_READ(p, children.next);
  int i;
  for (i = 0; i < MAX_ORPHANS; i = i + 1) {
    // Once we find the same element we started at, we know we've
    // iterated all children and we can exit the loop.
    if (next == &p->children) {
      pending->orphans[i] = NULL;
      break;
    }
    struct task_struct *task = container_of(next, struct task_struct, sibling);
    pending->orphans[i] = task;
    LOG_DEBUG("Pending check for new parent of %d ", BPF_CORE_READ(task, pid));
    next = BPF_CORE_READ(task, sibling.next);
  }
}

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

  struct process_event *event = output_temp();
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
  output_event(ctx, &events, event, sizeof(struct process_event),
               event->buffer.len);
  collect_orphans(tgid, p);
  return 0;
}

/// On task switch, check if there are pending orphans and signal
/// their parent changed.
SEC("raw_tracepoint/sched_switch")
int BPF_PROG(sched_switch) {
  u32 key = 0;
  struct pending_dead_process *pending =
      bpf_map_lookup_elem(&orphans_map, &key);
  if (!pending || !pending->dead_parent) {
    return 0;
  }
  pending->dead_parent = 0;
  int i;
  // TODO: use LOOP
  for (i = 0; i < MAX_ORPHANS; i = i + 1) {
    struct task_struct *orphan = pending->orphans[i];
    if (orphan == NULL)
      break;
    struct process_event *event = output_temp();
    if (!event)
      return 0;
    event->event_type = EVENT_CHANGE_PARENT;
    event->buffer.len = 0;
    event->timestamp = pending->timestamp;
    event->pid = BPF_CORE_READ(orphan, pid);
    event->change_parent.ppid = BPF_CORE_READ(orphan, parent, pid);
    LOG_DEBUG("New parent for %d: %d", event->pid, event->change_parent.ppid);
    output_event(ctx, &events, event, sizeof(struct process_event),
                 event->buffer.len);
  }
  return 0;
}

SEC("raw_tracepoint/cgroup_mkdir")
int BPF_PROG(cgroup_mkdir, struct cgroup *cgrp, const char *path) {
  pid_t tgid = interesting_tgid();
  if (tgid < 0)
    return 0;
  struct process_event *event = output_temp();
  if (!event)
    return 0;
  event->event_type = EVENT_CGROUP_MKDIR;
  event->timestamp = bpf_ktime_get_ns();
  event->pid = tgid;
  event->buffer.len = 0;
  event->cgroup_mkdir.id = BPF_CORE_READ(cgrp, kn, id);
  buffer_index_init(&event->buffer, &event->cgroup_mkdir.path);
  buffer_append_str(&event->buffer, &event->cgroup_mkdir.path, path,
                    BUFFER_MAX);
  output_event(ctx, &events, event, sizeof(struct process_event),
               event->buffer.len);
  return 0;
}
