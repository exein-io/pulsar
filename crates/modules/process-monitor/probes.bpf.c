// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "bpf/bpf_core_read.h"
#include "common.bpf.h"
#include "strncmp.bpf.h"
#include "bpf/bpf_helpers.h"
#include "buffer.bpf.h"
#include "get_path.bpf.h"
#include "interest_tracking.bpf.h"
#include "loop.bpf.h"
#include "output.bpf.h"
#include "vmlinux.h"

char LICENSE[] SEC("license") = "GPL v2";

#define EVENT_FORK 0
#define EVENT_EXEC 1
#define EVENT_EXIT 2
#define EVENT_CHANGE_PARENT 3
#define EVENT_CGROUP_MKDIR 4
#define EVENT_CGROUP_RMDIR 5
#define EVENT_CGROUP_ATTACH 6

#define MAX_ORPHANS 50
#define MAX_ORPHANS_UNROLL 30

#define MAX_PENDING_DEAD_PARENTS 30

#define MAX_CONTAINER_RUNTIMES 8

#define MNT_DEVNAME_MAX_BUF 256

#define CONTAINER_ID_MAX_BUF 72

#define DOCKER_CONTAINER_ENGINE 0
#define PODMAN_CONTAINER_ENGINE 1
#define UNKNOWN_CONTAINER_ENGINE -1
#define FAILED_READ_MEMORY_CGROUP_ID -2
#define FAILED_READ_CGROUP_NAME -3
#define FAILED_READ_PARENT_CGROUP_NAME -4
#define FAILED_PARSE_LIBPOD_CGROUP_NAME -5

struct namespaces
{
  unsigned int uts;
  unsigned int ipc;
  unsigned int mnt;
  unsigned int pid;
  unsigned int net;
  unsigned int time;
  unsigned int cgroup;
};

#define OPTION_NONE 0
#define OPTION_SOME 1

struct fork_event
{
  uid_t uid;
  pid_t ppid;
  struct namespaces namespaces;
  struct
  {
    u32 discriminant;
    struct
    {
      u32 container_engine;
      struct buffer_index cgroup_id;
    } container_id;
  } option_index;
};

struct exec_event
{
  uid_t uid;
  struct buffer_index filename;
  int argc;
  struct buffer_index argv;
  struct namespaces namespaces;
  struct
  {
    u32 discriminant;
    struct
    {
      int container_engine;
      struct buffer_index cgroup_id;
    } container_id;
  } option_index;
};

struct exit_event
{
  u32 exit_code;
};

struct change_parent_event
{
  pid_t ppid;
};

struct cgroup_event
{
  struct buffer_index path;
  u64 id;
};

struct cgroup_attach_event
{
  pid_t pid;
  struct buffer_index path;
  u64 id;
};

GLOBAL_INTEREST_MAP_DECLARATION;
MAP_RULES(m_rules);
MAP_CGROUP_RULES(m_cgroup_rules);

OUTPUT_MAP(process_event, {
  struct fork_event fork;
  struct exec_event exec;
  struct exit_event exit;
  struct change_parent_event change_parent;
  struct cgroup_event cgroup_mkdir;
  struct cgroup_event cgroup_rmdir;
  struct cgroup_attach_event cgroup_attach;
});

struct pending_dead_process
{
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
struct
{
  __uint(type, BPF_MAP_TYPE_QUEUE);
  __type(value, struct pending_dead_process);
  __uint(max_entries, MAX_PENDING_DEAD_PARENTS);
} orphans_map SEC(".maps");

struct mnt_devname_buf {
  char buf[MNT_DEVNAME_MAX_BUF];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct mnt_devname_buf);
  __uint(max_entries, 1);
} m_mnt_devname_buf SEC(".maps");

/*
Identifies the container engine and reads the cgroup id of a process
from its `task_struct` into an given array of character.

The array size MUST be greater than 72.

### Input:
    `char buf[]`: a pointer to an array of characters
    `size_t sz`: size of the buffer
    `int *offset`: a pointer to an integer
    `struct task_struct *cur_tsk`: a pointer to a process task struct

### Success:
    the return value is:
      - `0`: it's a docker container id
      - `1`: it's a podman container id
    and the characters array `buf` contains the id of the container
    at the position specified in the value pointed by `offset`.

### Error:
    if return value is less than `0`, in particular:
      - `-1`: no container or unknown container engine
      - `-2`: failed to read the id of the memory cgroup for the
              current kernel
      - `-3`: failed to read the cgroup name from the kernel memory
      - `-4`: failed to read the cgroup name of the the parent of
              the given process in the case of podman container
      - `-5`: failed to parse a `libpod-` cgroup name of the parent
              of the process after a successful parse of a `container`
              cgroup name for the given process
*/
static __always_inline int get_container_info(struct task_struct *cur_tsk, char *buf, size_t sz, int *offset)
{
  int cgrp_id;
  if (bpf_core_enum_value_exists(enum cgroup_subsys_id, memory_cgrp_id))
    cgrp_id = bpf_core_enum_value(enum cgroup_subsys_id, memory_cgrp_id);
  else
  {
    LOG_ERROR("failed to read memory cgroup id. make sure `CONFIG_MEMCG` is enabled in the kernel configuration\n");
    return FAILED_READ_MEMORY_CGROUP_ID;
  }

  const char *name = BPF_CORE_READ(cur_tsk, cgroups, subsys[cgrp_id], cgroup, kn, name);
  if (bpf_probe_read_kernel_str(buf, sz, name) < 0)
  {
    LOG_ERROR("failed to get kernfs node name: %s\n", buf);
    return FAILED_READ_CGROUP_NAME;
  }

  // Docker case
  if (STRNCMP(buf, 7, "docker-") == 0)
  {
    *offset = 7;
    return DOCKER_CONTAINER_ENGINE;
  }

  // Podman case
  //
  // the check for NULL character is needed to avoid collisions with
  // `containerd-` prefixed cgroup name
  if (STRNCMP(buf, 9, "container") == 0 && buf[9] == '\0')
  {

    const char *parent_name = BPF_CORE_READ(cur_tsk, cgroups, subsys[cgrp_id], cgroup, kn, parent, name);

    if (bpf_probe_read_kernel_str(buf, sz, parent_name) < 0)
    {
      LOG_ERROR("failed to get parent kernfs node name: %s\n", buf);
      return FAILED_READ_PARENT_CGROUP_NAME;
    }

    if (STRNCMP(buf, 7, "libpod-") == 0)
    {
      *offset = 7;
      return PODMAN_CONTAINER_ENGINE;
    }

    // Error podman step 2
    LOG_ERROR("failed parsing libpod id: %s\n", buf);
    return FAILED_PARSE_LIBPOD_CGROUP_NAME;
  }

  // No container or unknown container engine
  LOG_DEBUG("no container or unknown container engine. id: %s\n", buf);
  return UNKNOWN_CONTAINER_ENGINE;
}

// This hook intercepts new process creations, inherits interest for the child
// from the parent and emits a fork event.
SEC("raw_tracepoint/sched_process_fork")
int BPF_PROG(sched_process_fork, struct task_struct *parent,
             struct task_struct *child)
{
  pid_t parent_tgid = BPF_CORE_READ(parent, tgid);
  pid_t child_tgid = BPF_CORE_READ(child, tgid);

  char buf[CONTAINER_ID_MAX_BUF];

  __u32 key = 0;
  struct mnt_devname_buf *b_mnt_devname = bpf_map_lookup_elem(&m_mnt_devname_buf, &key);
  if (b_mnt_devname == 0) {
    return 0;
  }

  // const char *mnt_devname = BPF_CORE_READ(child, nsproxy, mnt_ns, root, mnt_devname);
  // if (bpf_probe_read_kernel_str(b_mnt_devname->buf, MNT_DEVNAME_MAX_BUF, mnt_devname) < 0)
  // {
  //   LOG_ERROR("failed to get mnt_devname");
  //   return 0;
  // }
  // LOG_ERROR("MNT_DEVNAME: %s\n", b_mnt_devname->buf);

  const unsigned char *dname = BPF_CORE_READ(child, nsproxy, mnt_ns, root, mnt.mnt_root, d_name.name);
  if (bpf_probe_read_kernel_str(b_mnt_devname->buf, MNT_DEVNAME_MAX_BUF, dname) < 0)
  {
    LOG_ERROR("failed to get mountname");
    return 0;
  }
  LOG_ERROR("MNT_DEVNAME: %s\n", b_mnt_devname->buf);

  // if parent process group matches the child one, we're forking a thread
  // and we ignore the event.
  if (parent_tgid == child_tgid)
  {
    return 0;
  }
  // Propagate whitelist to child
  tracker_fork(&GLOBAL_INTEREST_MAP, parent, child);
  LOG_DEBUG("fork %d %d", parent_tgid, child_tgid);

  struct process_event *event = init_process_event(EVENT_FORK, child_tgid);
  if (!event)
    return 0;

  u64 uid_gid = bpf_get_current_uid_gid();

  event->fork.uid = uid_gid;
  event->fork.ppid = parent_tgid;
  event->fork.namespaces.uts = BPF_CORE_READ(child, nsproxy, uts_ns, ns.inum);
  event->fork.namespaces.ipc = BPF_CORE_READ(child, nsproxy, ipc_ns, ns.inum);
  event->fork.namespaces.mnt = BPF_CORE_READ(child, nsproxy, mnt_ns, ns.inum);
  event->fork.namespaces.pid = BPF_CORE_READ(child, nsproxy, pid_ns_for_children, ns.inum);
  event->fork.namespaces.net = BPF_CORE_READ(child, nsproxy, net_ns, ns.inum);
  event->fork.namespaces.time = BPF_CORE_READ(child, nsproxy, time_ns, ns.inum);
  event->fork.namespaces.cgroup = BPF_CORE_READ(child, nsproxy, cgroup_ns, ns.inum);

  int id_offset;
  int container_engine = get_container_info(child, buf, CONTAINER_ID_MAX_BUF, &id_offset);
  if (container_engine < 0)
  {
    // TODO: print error ??
    event->fork.option_index.discriminant = OPTION_NONE;
    event->fork.option_index.container_id.container_engine = container_engine;
    event->fork.option_index.container_id.cgroup_id.start = 0;
    event->fork.option_index.container_id.cgroup_id.len = 0;
  }
  else
  {
    event->fork.option_index.discriminant = OPTION_SOME;
    event->fork.option_index.container_id.container_engine = container_engine;
    buffer_index_init(&event->buffer, &event->fork.option_index.container_id.cgroup_id);
    buffer_append_str(&event->buffer, &event->fork.option_index.container_id.cgroup_id,
                      buf + id_offset, CONTAINER_ID_MAX_BUF);

    LOG_DEBUG("fork - detected container with id: %s", buf + id_offset);
  }

  output_process_event(ctx, event);
  return 0;
}

SEC("raw_tracepoint/sched_process_exec")
int BPF_PROG(sched_process_exec, struct task_struct *p, pid_t old_pid,
             struct linux_binprm *bprm)
{
  pid_t tgid = bpf_get_current_pid_tgid() >> 32;

  char buf[CONTAINER_ID_MAX_BUF];

  struct process_event *event = init_process_event(EVENT_EXEC, tgid);
  if (!event)
    return 0;
  event->exec.argc = BPF_CORE_READ(bprm, argc);

  u64 uid_gid = bpf_get_current_uid_gid();

  event->exec.uid = uid_gid;
  event->exec.namespaces.uts = BPF_CORE_READ(p, nsproxy, uts_ns, ns.inum);
  event->exec.namespaces.ipc = BPF_CORE_READ(p, nsproxy, ipc_ns, ns.inum);
  event->exec.namespaces.mnt = BPF_CORE_READ(p, nsproxy, mnt_ns, ns.inum);
  event->exec.namespaces.pid = BPF_CORE_READ(p, nsproxy, pid_ns_for_children, ns.inum);
  event->exec.namespaces.net = BPF_CORE_READ(p, nsproxy, net_ns, ns.inum);
  event->exec.namespaces.time = BPF_CORE_READ(p, nsproxy, time_ns, ns.inum);
  event->exec.namespaces.cgroup = BPF_CORE_READ(p, nsproxy, cgroup_ns, ns.inum);

  int id_offset;
  int container_engine = get_container_info(p, buf, CONTAINER_ID_MAX_BUF, &id_offset);
  if (container_engine < 0)
  {
    event->exec.option_index.discriminant = OPTION_NONE;
    event->exec.option_index.container_id.cgroup_id.start = 0;
    event->exec.option_index.container_id.cgroup_id.len = 0;
  }
  else
  {
    event->exec.option_index.discriminant = OPTION_SOME;
    event->exec.option_index.container_id.container_engine = container_engine;
    buffer_index_init(&event->buffer, &event->exec.option_index.container_id.cgroup_id);
    buffer_append_str(&event->buffer, &event->exec.option_index.container_id.cgroup_id,
                      buf + id_offset, CONTAINER_ID_MAX_BUF);

    LOG_DEBUG("exec - detected container with id: %s", buf + id_offset);
  }

  // This is needed because the first MAX_IMAGE_LEN bytes of buffer will
  // be used as a lookup key for the target and whitelist maps and garbage
  // would make the search fail.
  u32 len_b = event->buffer.len;

  if (len_b > CONTAINER_ID_MAX_BUF)
  {
    LOG_ERROR("unexpected: container id buffer is too long");
    return 0;
  }

  u64 *position = event->buffer.buffer + len_b;

  __builtin_memset((char *)position, 0, MAX_IMAGE_LEN);

  // We want to get the absolute path of the executable we're running.
  // When executing a process with a relative path, bprm->filename won't be
  // enough and we'll have to do a full path traversal. When starts with /
  // though, we can just copy it, as an optimization.
  const char *bprm_filename = BPF_CORE_READ(bprm, filename);
  char first_character = 0;
  bpf_core_read(&first_character, 1, bprm_filename);
  if (first_character == '/')
  {
    buffer_index_init(&event->buffer, &event->exec.filename);
    buffer_append_str(&event->buffer, &event->exec.filename, bprm_filename,
                      BUFFER_MAX);
  }
  else
  {
    struct path path = BPF_CORE_READ(bprm, file, f_path);
    get_path_str(&path, &event->buffer, &event->exec.filename);
  }

  char *image = (char *)&event->buffer.buffer;

  // Check target and whitelist
  tracker_check_rules(&GLOBAL_INTEREST_MAP, &m_rules, p, image);

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct mm_struct *mm = BPF_CORE_READ(task, mm);
  long start = BPF_CORE_READ(mm, arg_start);
  long end = BPF_CORE_READ(mm, arg_end);
  int len = end - start;
  buffer_index_init(&event->buffer, &event->exec.argv);
  buffer_append_user_memory(&event->buffer, &event->exec.argv, (void *)start,
                            len);

  output_process_event(ctx, event);

  return 0;
}

// Context for loop_collect_orphan
struct ctx_collect_orphan
{
  // Next process to check
  struct list_head *next;
  // End of list
  struct list_head *last;
  // Output data structure where orphans are saved
  struct pending_dead_process pending;
};

// Used to iterate over the children of a dead process and collect them
// into a `struct pending_dead_process`. Used in the collect_orphans loop.
static __always_inline long loop_collect_orphan(u32 i, void *callback_ctx)
{
  struct ctx_collect_orphan *c = callback_ctx;
  // Once we find the same element we started at, we know we've
  // iterated all children and we can exit the loop.
  if (c->next == c->last)
  {
    return LOOP_STOP;
  }
  struct task_struct *task = container_of(c->next, struct task_struct, sibling);
  if (i < MAX_ORPHANS) // satisfy verifier (always true)
    c->pending.orphans[i] = task;

  c->next = BPF_CORE_READ(task, sibling.next);
  return LOOP_CONTINUE;
}

// When a process exits, we have to add all its children to orphans_map. This
// will be checked as soon as possibile (the scheduler iteration which happens
// immediately after an exit syscall) for changes to a process parent.
static __always_inline void collect_orphans(pid_t tgid, struct task_struct *p)
{
  LOG_DEBUG("%d is DEAD ", tgid);

  // Collect orphans by iterating the dead process children
  struct ctx_collect_orphan c;
  __builtin_memset(&c.pending, 0, sizeof(struct pending_dead_process));
  c.next = BPF_CORE_READ(p, children.next);
  c.last = &p->children;
  c.pending.dead_parent = tgid;
  c.pending.timestamp = bpf_ktime_get_ns();

  LOOP(MAX_ORPHANS, MAX_ORPHANS_UNROLL, loop_collect_orphan, &c);
  // Log a warning if we couln't process all children
  if (c.next != c.last)
  {
    LOG_ERROR("Couldn't iterate all children. Too many of them");
  }
  u64 r = bpf_map_push_elem(&orphans_map, &c.pending, 0);
  if (r)
  {
    LOG_ERROR("Pushing to orphans_map failed: %d", r);
  }
}

// This is attached to tracepoint:sched:sched_process_exit
SEC("raw_tracepoint/sched_process_exit")
int BPF_PROG(sched_process_exit, struct task_struct *p)
{
  pid_t tgid = BPF_CORE_READ(p, group_leader, pid);

  // We want to ignore threads and focus on whole processes, so we have
  // to wait for the whole process group to exit. Unfortunately, checking
  // if the current task's pid matches its tgid is not enough because
  // the main thread could exit before the child one.
  if (BPF_CORE_READ(p, signal, live.counter) > 0)
  {
    return 0;
  }

  // cleanup resources from map_interest
  if (!tracker_remove(&GLOBAL_INTEREST_MAP, p))
  {
    LOG_DEBUG("%d not found in map_interest during exit", tgid);
    // Multiple threads may exit at the same time, causing the check above
    // to pass multiple times. Since we want to generate only one event,
    // we'll consider a missing entry in map_interest as a signal that
    // we've already emitted the exit event.
    return 0;
  }

  struct process_event *event = init_process_event(EVENT_EXIT, tgid);
  if (!event)
    return 0;
  // NOTE: here we're assuming the exit code is set by the last exiting thread
  event->exit.exit_code = BPF_CORE_READ(p, exit_code) >> 8;

  LOG_DEBUG("exitited at %ld with code %d", event->timestamp,
            event->exit.exit_code);
  output_process_event(ctx, event);
  collect_orphans(tgid, p);
  return 0;
}

// Context for loop_orphan_adopted
struct ctx_orphan_adopted
{
  // eBPF program context used for emitting events
  void *ctx;
  // list of pending orphans we should check
  struct pending_dead_process pending;
};

// Used to iterate over all the orphans left by a dead process and
// emit an event with their new parent. Used in the sched_switch loop.
static __always_inline long loop_orphan_adopted(u32 i, void *callback_ctx)
{
  struct ctx_orphan_adopted *c = callback_ctx;
  if (i >= MAX_ORPHANS) // satisfy verifier (never true)
    return LOOP_STOP;
  struct task_struct *orphan = c->pending.orphans[i];
  if (orphan == NULL) // true when we're done
    return LOOP_STOP;
  pid_t tgid = BPF_CORE_READ(orphan, pid);
  struct process_event *event = init_process_event(EVENT_CHANGE_PARENT, tgid);
  if (!event) // memory error
    return LOOP_STOP;
  event->change_parent.ppid = BPF_CORE_READ(orphan, parent, pid);
  LOG_DEBUG("New parent for %d: %d", event->pid, event->change_parent.ppid);
  output_process_event(c->ctx, event);
  return LOOP_CONTINUE;
}

/// On task switch, check if there are pending orphans and signal
/// their parent changed.
SEC("raw_tracepoint/sched_switch")
int BPF_PROG(sched_switch)
{
  struct ctx_orphan_adopted c;
  pid_t first = 0;

  for (int i = 0; i < 5; i++)
  {
    if (bpf_map_pop_elem(&orphans_map, &c.pending))
    {
      return 0;
    }
    // Make sure the loop doesn't process the same dead parent multiple times
    if (first == 0)
    {
      first = c.pending.dead_parent;
    }
    else if (first == c.pending.dead_parent)
    {
      // push the item back
      bpf_map_push_elem(&orphans_map, &c.pending, 0);
      break;
    }

    // sched_switch could be called too soon, before the new parent
    // of the child is set.
    struct task_struct *first_orphan = c.pending.orphans[0];
    pid_t first_new_parent = BPF_CORE_READ(first_orphan, parent, pid);
    if (c.pending.dead_parent == first_new_parent)
    {
      LOG_DEBUG("No new parent set yet for children of dead %d",
                c.pending.dead_parent);
      // push the item back
      bpf_map_push_elem(&orphans_map, &c.pending, 0);
    }
    else
    {
      c.ctx = ctx;
      LOOP(MAX_ORPHANS, MAX_ORPHANS_UNROLL, loop_orphan_adopted, &c);
    }
  }
  return 0;
}

SEC("raw_tracepoint/cgroup_mkdir")
int BPF_PROG(cgroup_mkdir, struct cgroup *cgrp, const char *path)
{
  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return 0;
  struct process_event *event = init_process_event(EVENT_CGROUP_MKDIR, tgid);
  if (!event)
    return 0;
  event->buffer.len = 0;
  event->cgroup_mkdir.id = BPF_CORE_READ(cgrp, kn, id);
  buffer_index_init(&event->buffer, &event->cgroup_mkdir.path);
  buffer_append_str(&event->buffer, &event->cgroup_mkdir.path, path,
                    BUFFER_MAX);
  output_process_event(ctx, event);
  return 0;
}

SEC("raw_tracepoint/cgroup_rmdir")
int BPF_PROG(cgroup_rmdir, struct cgroup *cgrp, const char *path)
{
  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return 0;
  struct process_event *event = init_process_event(EVENT_CGROUP_RMDIR, tgid);
  if (!event)
    return 0;
  event->cgroup_rmdir.id = BPF_CORE_READ(cgrp, kn, id);
  buffer_index_init(&event->buffer, &event->cgroup_rmdir.path);
  buffer_append_str(&event->buffer, &event->cgroup_rmdir.path, path,
                    BUFFER_MAX);
  output_process_event(ctx, event);
  return 0;
}

SEC("raw_tracepoint/cgroup_attach_task")
int BPF_PROG(cgroup_attach_task, struct cgroup *cgrp, const char *path,
             struct task_struct *task)
{
  tracker_check_cgroup_rules(&GLOBAL_INTEREST_MAP, &m_cgroup_rules, task, path);

  // If the event is of interest, emit it as usual
  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return 0;
  struct process_event *event = init_process_event(EVENT_CGROUP_ATTACH, tgid);
  if (!event)
    return 0;
  event->cgroup_attach.id = BPF_CORE_READ(cgrp, kn, id);
  event->cgroup_attach.pid = BPF_CORE_READ(task, tgid);
  buffer_index_init(&event->buffer, &event->cgroup_attach.path);
  buffer_append_str(&event->buffer, &event->cgroup_attach.path, path,
                    BUFFER_MAX);
  output_process_event(ctx, event);
  return 0;
}
