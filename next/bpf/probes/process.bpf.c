// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "pulsar/abi/process.h"

#include "vmlinux.h"

#include "bpf/bpf_core_read.h"

#include "pulsar/buffer.bpf.h"
#include "pulsar/common.bpf.h"
#include "pulsar/get_path.bpf.h"
#include "pulsar/interest_tracking.bpf.h"
#include "pulsar/kernfs_node_compat.h"
#include "pulsar/loop.bpf.h"
#include "pulsar/ring.bpf.h"
#include "pulsar/strncmp.bpf.h"

char LICENSE[] SEC("license") = "GPL v2";

#define MAX_ORPHANS 45
#define MAX_ORPHANS_UNROLL 30

#define MAX_PENDING_DEAD_PARENTS 30

#define MAX_CONTAINER_RUNTIMES 8

#define CONTAINER_ID_MAX_BUF PULSAR_CONTAINER_NAME_MAX

#define DOCKER_CONTAINER_ENGINE 0
#define PODMAN_CONTAINER_ENGINE 1
#define UNKNOWN_CONTAINER_ENGINE -1
#define FAILED_READ_MEMORY_CGROUP_ID -2
#define FAILED_READ_CGROUP_NAME -3
#define FAILED_READ_PARENT_CGROUP_NAME -4
#define FAILED_PARSE_LIBPOD_CGROUP_NAME -5

GLOBAL_INTEREST_MAP_DECLARATION;
MAP_RULES(m_rules);

PULSAR_SCRATCH_TYPE(pulsar_process_exec);

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
  __uint(type, BPF_MAP_TYPE_QUEUE);
  __type(value, struct pending_dead_process);
  __uint(max_entries, MAX_PENDING_DEAD_PARENTS);
} orphans_map SEC(".maps");

/*
Buffer for reading container id of a process. The Container ID is located at
`buf[offset]`
 */
struct container_id_buffer {
  char buf[CONTAINER_ID_MAX_BUF];
  size_t offset;
};

/*
Identifies the container engine and reads the cgroup id of a process
from its `task_struct` into a given `container_id_buffer`.

### Input:
    `struct task_struct *cur_tsk`: a pointer to a process task struct
    `struct container_id_buffer *c_id_buf`: a pointer to the buffer

### Success:
    the return value is:
      - `0`: it's a docker container id
      - `1`: it's a podman container id
    and `c_id_buf->buf` contains the id of the container at the position
    specified in the value pointed by `c_id_buf->offset`.

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
static __always_inline int
get_container_info(struct task_struct *cur_tsk,
                   struct container_id_buffer *c_id_buf) {
  int cgrp_id;
  struct container_id_buffer parent_buf;

  if (bpf_core_enum_value_exists(enum cgroup_subsys_id, memory_cgrp_id))
    cgrp_id = bpf_core_enum_value(enum cgroup_subsys_id, memory_cgrp_id);
  else {
    LOG_ERROR("failed to read memory cgroup id. make sure `CONFIG_MEMCG` is "
              "enabled in the kernel configuration\n");
    return FAILED_READ_MEMORY_CGROUP_ID;
  }

  struct kernfs_node *kn =
      BPF_CORE_READ(cur_tsk, cgroups, subsys[cgrp_id], cgroup, kn);
  const char *name;

  // handle kernfs compat if kernel < 6.15
  if (bpf_core_field_exists(kn->__parent)) {
    name = BPF_CORE_READ(kn, name);
  } else {
    struct kernfs_node___compat *kn_compat = (void *)kn;
    name = BPF_CORE_READ(kn_compat, name);
  }

  if (bpf_core_read_str(c_id_buf->buf, CONTAINER_ID_MAX_BUF, name) < 0) {
    LOG_ERROR("failed to get kernfs node name: %s\n", c_id_buf->buf);
    return FAILED_READ_CGROUP_NAME;
  }

  const char *parent_name = NULL;

  // handle kernfs compat if kernel < 6.15
  if (bpf_core_field_exists(kn->__parent)) {
    struct kernfs_node *parent_kn = BPF_CORE_READ(kn, __parent);

    if (parent_kn != NULL) {
      parent_name = BPF_CORE_READ(kn, __parent, name);
      if (bpf_core_read_str(parent_buf.buf, CONTAINER_ID_MAX_BUF, parent_name) <
          0) {
        LOG_ERROR("failed to get parent kernfs node name: %s\n",
                  parent_buf.buf);
        return FAILED_READ_PARENT_CGROUP_NAME;
      }
    }
  } else {
    struct kernfs_node___compat *kn_compat = (void *)kn;
    struct kernfs_node___compat *parent_kn = BPF_CORE_READ(kn_compat, parent);

    if (parent_kn != NULL) {
      parent_name = BPF_CORE_READ(kn_compat, parent, name);
      if (bpf_core_read_str(parent_buf.buf, CONTAINER_ID_MAX_BUF, parent_name) <
          0) {
        LOG_ERROR("failed to get parent kernfs node name: %s\n",
                  parent_buf.buf);
        return FAILED_READ_PARENT_CGROUP_NAME;
      }
    }
  }

  // For Docker containers, there are two cgroup path formats:
  //
  // 1.
  // `0::/system.slice/docker-d4ea646fc22c701dbb146e52db4e9125dcca2eebb2f5552f90fedbb28a0f0716.scope`
  //    This is typical for systemd cgroup driver. In this case, the last
  //    node contains the `docker-` prefix followed by the container ID.
  // 2.
  // `0::/docker/2cf2e0be458a80acb354c953f7bb03de5d2d277dfcb8ebaa6575f95668a0c15f`
  //    This is typical for cgroupfs driver. In this case, the parent node is
  //    `docker` and the child node contains the container ID.

  // Case 1.
  if (STRNCMP(c_id_buf->buf, 7, "docker-") == 0) {
    c_id_buf->offset = 7;
    return DOCKER_CONTAINER_ENGINE;
  }

  // Case 2.
  //
  // The check for NULL character is needed to make sure it is the full kernfs
  // node name.
  if (STRNCMP(parent_buf.buf, 6, "docker") == 0 && parent_buf.buf[6] == '\0') {
    // The last node is unprefixed, it contains just container ID.
    c_id_buf->offset = 0;
    return DOCKER_CONTAINER_ENGINE;
  }

  // Podman case
  //
  // the check for NULL character is needed to avoid collisions with
  // `containerd-` prefixed cgroup name
  if (STRNCMP(c_id_buf->buf, 9, "container") == 0 && c_id_buf->buf[9] == '\0') {
    // Read `parent_name` to the main buffer `buf`.
    if (parent_name == NULL ||
        bpf_core_read_str(c_id_buf->buf, CONTAINER_ID_MAX_BUF, parent_name) <
            0) {
      LOG_ERROR("failed to get parent kernfs node name: %s\n", c_id_buf->buf);
      return FAILED_READ_PARENT_CGROUP_NAME;
    }

    if (STRNCMP(c_id_buf->buf, 7, "libpod-") == 0) {
      c_id_buf->offset = 7;
      return PODMAN_CONTAINER_ENGINE;
    }

    // Error podman step 2
    LOG_ERROR("failed parsing libpod id: %s\n", c_id_buf->buf);
    return FAILED_PARSE_LIBPOD_CGROUP_NAME;
  }

  // No container or unknown container engine
  LOG_DEBUG("no container or unknown container engine. id: %s\n",
            c_id_buf->buf);
  return UNKNOWN_CONTAINER_ENGINE;
}

// Reads the namespaces of @task. A task that has already released them (it is
// exiting) gets PULSAR_PROCESS_MISSING_NAMESPACES.
static __always_inline void read_namespaces(struct task_struct *task,
                                            struct pulsar_namespaces *ns,
                                            u32 *missing) {
  struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
  if (!nsproxy) {
    *missing |= PULSAR_PROCESS_MISSING_NAMESPACES;
    return;
  }
  ns->uts = BPF_CORE_READ(nsproxy, uts_ns, ns.inum);
  ns->ipc = BPF_CORE_READ(nsproxy, ipc_ns, ns.inum);
  ns->mnt = BPF_CORE_READ(nsproxy, mnt_ns, ns.inum);
  ns->pid = BPF_CORE_READ(nsproxy, pid_ns_for_children, ns.inum);
  ns->net = BPF_CORE_READ(nsproxy, net_ns, ns.inum);
  ns->time = BPF_CORE_READ(nsproxy, time_ns, ns.inum);
  ns->cgroup = BPF_CORE_READ(nsproxy, cgroup_ns, ns.inum);
}

// Fills @container from the result of get_container_info. "No container" is
// known (PULSAR_CONTAINER_NONE); a failed read gets
// PULSAR_PROCESS_MISSING_CONTAINER.
static __always_inline void
fill_container(struct pulsar_container *container, u32 *missing, int engine,
               struct container_id_buffer *c_id_buf) {
  switch (engine) {
  case DOCKER_CONTAINER_ENGINE:
    container->engine = PULSAR_CONTAINER_DOCKER;
    break;
  case PODMAN_CONTAINER_ENGINE:
    container->engine = PULSAR_CONTAINER_PODMAN;
    break;
  case UNKNOWN_CONTAINER_ENGINE:
    container->engine = PULSAR_CONTAINER_NONE;
    return;
  default:
    *missing |= PULSAR_PROCESS_MISSING_CONTAINER;
    return;
  }
  container->id_offset = c_id_buf->offset;
  __builtin_memcpy(container->name, c_id_buf->buf, sizeof(container->name));
  LOG_DEBUG("detected container with id: %s", c_id_buf->buf + c_id_buf->offset);
}

// This hook intercepts new process creations, inherits interest for the child
// from the parent and emits a fork event.
SEC("raw_tracepoint/sched_process_fork")
int BPF_PROG(sched_process_fork, struct task_struct *parent,
             struct task_struct *child) {
  pid_t parent_tgid = BPF_CORE_READ(parent, tgid);
  pid_t child_tgid = BPF_CORE_READ(child, tgid);

  struct container_id_buffer c_id_buf;

  // if parent process group matches the child one, we're forking a thread
  // and we ignore the event.
  if (parent_tgid == child_tgid) {
    return 0;
  }
  // Propagate whitelist to child
  tracker_fork(&GLOBAL_INTEREST_MAP, parent, child);
  LOG_DEBUG("fork %d %d", parent_tgid, child_tgid);

  // Done before reserving, so the reservation is held only while writing.
  // Zeroed because the whole name is copied into the record.
  __builtin_memset(&c_id_buf, 0, sizeof(c_id_buf));
  int container_engine = get_container_info(child, &c_id_buf);

  struct pulsar_process_fork_record *rec = PULSAR_RESERVE(
      struct pulsar_process_fork_record, PULSAR_PROCESS_FORK, child);
  if (!rec)
    return 0;
  read_namespaces(child, &rec->body.namespaces, &rec->body.missing);
  fill_container(&rec->body.container, &rec->body.missing, container_engine,
                 &c_id_buf);
  pulsar_submit(rec);
  return 0;
}

SEC("raw_tracepoint/sched_process_exec")
int BPF_PROG(sched_process_exec, struct task_struct *p, pid_t old_pid,
             struct linux_binprm *bprm) {
  struct container_id_buffer c_id_buf;
  // Zeroed because the whole name is copied into the record.
  __builtin_memset(&c_id_buf, 0, sizeof(c_id_buf));
  int container_engine = get_container_info(p, &c_id_buf);

  struct pulsar_process_exec_scratch *rec = PULSAR_SCRATCH(
      struct pulsar_process_exec_scratch, PULSAR_PROCESS_EXEC, p);
  if (!rec)
    return 0;
  rec->body.argc = BPF_CORE_READ(bprm, argc);
  read_namespaces(p, &rec->body.namespaces, &rec->body.missing);
  fill_container(&rec->body.container, &rec->body.missing, container_engine,
                 &c_id_buf);

  // We want to get the absolute path of the executable we're running.
  // When executing a process with a relative path, bprm->filename won't be
  // enough and we'll have to do a full path traversal. When starts with /
  // though, we can just copy it, as an optimization.
  const char *bprm_filename = BPF_CORE_READ(bprm, filename);
  char first_character = 0;
  bpf_core_read(&first_character, 1, bprm_filename);
  if (first_character == '/') {
    buffer_index_init(&rec->buffer, &rec->body.filename);
    buffer_append_str(&rec->buffer, &rec->body.filename, bprm_filename,
                      BUFFER_MAX, 0);
  } else {
    struct path path = BPF_CORE_READ(bprm, file, f_path);
    get_path_str(&path, &rec->buffer, &rec->body.filename);
  }

  // Check target and whitelist. The filename is the first field of the
  // buffer; when it is missing, the buffer holds bytes of an older record.
  if (rec->body.filename.status != PULSAR_FIELD_MISSING) {
    char *image = (char *)rec->buffer.data;
    tracker_check_rules(&GLOBAL_INTEREST_MAP, &m_rules, p, image);
  }

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct mm_struct *mm = BPF_CORE_READ(task, mm);
  u64 start = BPF_CORE_READ(mm, arg_start);
  u64 end = BPF_CORE_READ(mm, arg_end);
  u64 len = end > start ? end - start : 0;
  buffer_index_init(&rec->buffer, &rec->body.argv);

  int r = buffer_append_user_memory(&rec->buffer, &rec->body.argv,
                                    (void *)start, len);
  if (r < 0) {
    // We are logging this, but not discarding event.
    // It is better to have exec event with missing argv than
    // to miss the event.
    LOG_DEBUG("failed to append argv to buffer");
  }

  PULSAR_OUTPUT(rec);

  return 0;
}

// Context for loop_collect_orphan
struct ctx_collect_orphan {
  // Next process to check
  struct list_head *next;
  // End of list
  struct list_head *last;
  // Output data structure where orphans are saved
  struct pending_dead_process pending;
};

// Used to iterate over the children of a dead process and collect them
// into a `struct pending_dead_process`. Used in the collect_orphans loop.
static __always_inline long loop_collect_orphan(u32 i, void *callback_ctx) {
  struct ctx_collect_orphan *c = callback_ctx;
  // Once we find the same element we started at, we know we've
  // iterated all children and we can exit the loop.
  if (c->next == c->last) {
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
static __always_inline void collect_orphans(pid_t tgid, struct task_struct *p) {
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
  if (c.next != c.last) {
    LOG_ERROR("Couldn't iterate all children. Too many of them");
  }
  u64 r = bpf_map_push_elem(&orphans_map, &c.pending, 0);
  if (r) {
    LOG_ERROR("Pushing to orphans_map failed: %d", r);
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
  if (!tracker_remove(&GLOBAL_INTEREST_MAP, p)) {
    LOG_DEBUG("%d not found in map_interest during exit", tgid);
    // Multiple threads may exit at the same time, causing the check above
    // to pass multiple times. Since we want to generate only one event,
    // we'll consider a missing entry in map_interest as a signal that
    // we've already emitted the exit event.
    return 0;
  }

  struct pulsar_process_exit_record *rec =
      PULSAR_RESERVE(struct pulsar_process_exit_record, PULSAR_PROCESS_EXIT, p);
  if (rec) {
    // NOTE: here we're assuming the exit code is set by the last exiting
    // thread
    rec->body.exit_code = BPF_CORE_READ(p, exit_code) >> 8;
    LOG_DEBUG("exited with code %d", rec->body.exit_code);
    pulsar_submit(rec);
  }
  collect_orphans(tgid, p);
  return 0;
}

// Context for loop_orphan_adopted
struct ctx_orphan_adopted {
  // list of pending orphans we should check
  struct pending_dead_process pending;
};

// Used to iterate over all the orphans left by a dead process and
// emit an event with their new parent. Used in the sched_switch loop.
static __always_inline long loop_orphan_adopted(u32 i, void *callback_ctx) {
  struct ctx_orphan_adopted *c = callback_ctx;
  if (i >= MAX_ORPHANS) // satisfy verifier (never true)
    return LOOP_STOP;
  struct task_struct *orphan = c->pending.orphans[i];
  if (orphan == NULL) // true when we're done
    return LOOP_STOP;
  struct pulsar_process_change_parent_record *rec =
      PULSAR_RESERVE(struct pulsar_process_change_parent_record,
                     PULSAR_PROCESS_CHANGE_PARENT, orphan);
  if (!rec) // ring full
    return LOOP_STOP;
  rec->body.ppid = BPF_CORE_READ(orphan, parent, pid);
  LOG_DEBUG("New parent for %d: %d", rec->header.subject.tgid, rec->body.ppid);
  pulsar_submit(rec);
  return LOOP_CONTINUE;
}

/// On task switch, check if there are pending orphans and signal
/// their parent changed.
SEC("raw_tracepoint/sched_switch")
int BPF_PROG(sched_switch) {
  struct ctx_orphan_adopted c;
  pid_t first = 0;

#pragma unroll 5
  for (int i = 0; i < 5; i++) {
    if (bpf_map_pop_elem(&orphans_map, &c.pending)) {
      break;
    }
    // Make sure the loop doesn't process the same dead parent multiple times
    if (first == 0) {
      first = c.pending.dead_parent;
    } else if (first == c.pending.dead_parent) {
      // push the item back
      bpf_map_push_elem(&orphans_map, &c.pending, 0);
      break;
    }

    // sched_switch could be called too soon, before the new parent
    // of the child is set.
    struct task_struct *first_orphan = c.pending.orphans[0];
    pid_t first_new_parent = BPF_CORE_READ(first_orphan, parent, pid);
    if (c.pending.dead_parent == first_new_parent) {
      LOG_DEBUG("No new parent set yet for children of dead %d",
                c.pending.dead_parent);
      // push the item back
      bpf_map_push_elem(&orphans_map, &c.pending, 0);
    } else {
      LOOP(MAX_ORPHANS, MAX_ORPHANS_UNROLL, loop_orphan_adopted, &c);
    }
  }
  return 0;
}

static __always_inline void on_creds_change(void *ctx, struct cred *new) {
  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return;
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct pulsar_process_creds_change_record *rec =
      PULSAR_RESERVE(struct pulsar_process_creds_change_record,
                     PULSAR_PROCESS_CREDS_CHANGE, task);
  if (!rec)
    return;
  rec->body.uid = BPF_CORE_READ(new, uid.val);
  rec->body.gid = BPF_CORE_READ(new, gid.val);
  pulsar_submit(rec);
}

PULSAR_LSM_HOOK(task_fix_setuid, struct cred *, new, struct cred *, old, int,
                flags);
static __always_inline void on_task_fix_setuid(void *ctx, struct cred *new,
                                               struct cred *old, int flags) {
  on_creds_change(ctx, new);
}

PULSAR_LSM_HOOK(task_fix_setgid, struct cred *, new, struct cred *, old, int,
                flags);
static __always_inline void on_task_fix_setgid(void *ctx, struct cred *new,
                                               struct cred *old, int flags) {
  on_creds_change(ctx, new);
}

SEC("kprobe/commit_creds")
int BPF_KPROBE(commit_creds, struct cred *new) {
  on_creds_change(ctx, new);
  return 0;
}
