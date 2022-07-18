// SPDX-License-Identifier: GPL-2.0
#include "common.bpf.h"

char LICENSE[] SEC("license") = "GPL";

int my_pid = 0;

#define FILE_CREATED 0
#define FILE_DELETED 1
#define FILE_OPENED 2
#define NAME_MAX 1024
#define MAX_PATH_COMPONENTS 20

struct event_t {
  u64 timestamp;
  pid_t pid;
  u32 event;
  char filename[NAME_MAX];
  int flags;
};

struct bpf_map_def SEC("maps/event") eventmem = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct event_t),
    .max_entries = 1,
};

// used to send events to userspace
struct bpf_map_def SEC("maps/events") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 0,
};

// get_path_str was copied and adapted from Tracee
static __always_inline void get_path_str(struct path *path,
                                         char buf[NAME_MAX]) {
  struct path f_path;
  bpf_probe_read_kernel(&f_path, sizeof(struct path), path);
  char slash = '/';
  int zero = 0;
  struct dentry *dentry = f_path.dentry;
  struct vfsmount *vfsmnt = f_path.mnt;
  struct mount *mnt_parent_p;

  struct mount *mnt_p = container_of(vfsmnt, struct mount, mnt);
  bpf_probe_read_kernel(&mnt_parent_p, sizeof(struct mount *),
                        &mnt_p->mnt_parent);

  u32 buf_off = (NAME_MAX >> 1);
  struct dentry *mnt_root;
  struct dentry *d_parent;
  struct qstr d_name;
  unsigned int len;
  unsigned int off;
  int sz;

  if (buf == NULL)
    return;

#pragma unroll
  for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
    mnt_root = (struct dentry *)BPF_CORE_READ(vfsmnt, mnt_root);
    struct dentry *d_parent = BPF_CORE_READ(dentry, d_parent);
    if (dentry == mnt_root || dentry == d_parent) {
      if (dentry != mnt_root) {
        // We reached root, but not mount root - escaped?
        break;
      }
      if (mnt_p != mnt_parent_p) {
        // We reached root, but not global root - continue with mount point path
        bpf_probe_read_kernel(&dentry, sizeof(struct dentry *),
                              &mnt_p->mnt_mountpoint);
        bpf_probe_read_kernel(&mnt_p, sizeof(struct mount *),
                              &mnt_p->mnt_parent);
        bpf_probe_read_kernel(&mnt_parent_p, sizeof(struct mount *),
                              &mnt_p->mnt_parent);
        vfsmnt = &mnt_p->mnt;
        continue;
      }
      // Global root - path fully parsed
      break;
    }
    // Add this dentry name to path
    d_name = BPF_CORE_READ(dentry, d_name);
    len = (d_name.len + 1) & (NAME_MAX - 1);
    off = buf_off - len;

    // Is string buffer big enough for dentry name?
    sz = 0;
    if (off <= buf_off) { // verify no wrap occurred
      len = len & ((NAME_MAX >> 1) - 1);
      sz = bpf_probe_read_kernel_str(&(buf[off & ((NAME_MAX >> 1) - 1)]), len,
                                     (void *)d_name.name);
    } else
      break;
    if (sz > 1) {
      buf_off -= 1; // remove null byte termination with slash sign
      bpf_probe_read_kernel(&(buf[buf_off & (NAME_MAX - 1)]), 1, &slash);
      buf_off -= sz - 1;
    } else {
      // If sz is 0 or 1 we have an error (path can't be null nor an empty
      // string)
      break;
    }
    dentry = d_parent;
  }

  if (buf_off == (NAME_MAX >> 1)) {
    // memfd files have no path in the filesystem -> extract their name
    buf_off = 0;
    d_name = BPF_CORE_READ(dentry, d_name);
    bpf_probe_read_kernel_str(&(buf[0]), NAME_MAX, (void *)d_name.name);
  } else {
    // Add leading slash
    buf_off -= 1;
    bpf_probe_read_kernel(&(buf[buf_off & (NAME_MAX - 1)]), 1, &slash);
    // Null terminate the path string
    bpf_probe_read_kernel(&(buf[(NAME_MAX >> 1) - 1]), 1, &zero);

    // Copy string to the start
    int total_len = NAME_MAX - buf_off;
    bpf_probe_read_kernel(buf, total_len & (NAME_MAX - 1),
                          buf + (buf_off & NAME_MAX - 1));
  }
}

// get_dentry_path_str was copied and adapted from Tracee
static __always_inline void get_dentry_path_str(struct dentry *dentry,
                                                char buf[NAME_MAX]) {
  char slash = '/';
  int zero = 0;

  // TODO: remove >> 1?
  u32 buf_off = (NAME_MAX >> 1);

  if (buf == NULL)
    return;

#pragma unroll
  for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
    struct dentry *d_parent = BPF_CORE_READ(dentry, d_parent);

    if (dentry == d_parent) {
      break;
    }
    // Add this dentry name to path
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    unsigned int len = (d_name.len + 1) & (NAME_MAX - 1);
    unsigned int off = buf_off - len;
    // Is string buffer big enough for dentry name?
    int sz = 0;
    if (off <= buf_off) { // verify no wrap occurred
      len = len & ((NAME_MAX >> 1) - 1);
      sz = bpf_probe_read_kernel_str(&(buf[off & ((NAME_MAX >> 1) - 1)]), len,
                                     (void *)d_name.name);
    } else {
      break;
    }
    if (sz > 1) {
      buf_off -= 1; // remove null byte termination with slash sign
      bpf_probe_read_kernel(&(buf[buf_off & (NAME_MAX - 1)]), 1, &slash);
      buf_off -= sz - 1;
    } else {
      // If sz is 0 or 1 we have an error (path can't be null nor an empty
      // string)
      break;
    }
    dentry = d_parent;
  }

  if (buf_off == (NAME_MAX >> 1)) {
    // memfd files have no path in the filesystem -> extract their name
    buf_off = 0;
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    bpf_probe_read_kernel_str(&(buf[0]), NAME_MAX, (void *)d_name.name);
  } else {
    // Add leading slash
    buf_off -= 1;
    bpf_probe_read_kernel(&(buf[buf_off & (NAME_MAX - 1)]), 1, &slash);
    // Null terminate the path string
    bpf_probe_read_kernel(&(buf[(NAME_MAX >> 1) - 1]), 1, &zero);
    // Copy string to the start
    int total_len = NAME_MAX - buf_off;
    bpf_probe_read_kernel(buf, total_len & (NAME_MAX - 1),
                          buf + (buf_off & NAME_MAX - 1));
  }
}

SEC("kprobe/security_inode_create")
int security_inode_create(struct pt_regs *ctx) {
  pid_t tgid = interesting_tgid();
  if (tgid < 0)
    return 0;

  u32 key = 0;
  struct event_t *event = bpf_map_lookup_elem(&eventmem, &key);
  if (!event)
    return 0;
  struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
  get_dentry_path_str(dentry, event->filename);
  event->event = FILE_CREATED;
  event->timestamp = bpf_ktime_get_ns();
  event->pid = tgid;

  LOG_DEBUG("create %s", event->filename);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct event_t));
  return 0;
}

SEC("kprobe/security_inode_unlink")
int security_inode_unlink(struct pt_regs *ctx) {
  pid_t tgid = interesting_tgid();
  if (tgid < 0)
    return 0;

  u32 key = 0;
  struct event_t *event = bpf_map_lookup_elem(&eventmem, &key);
  if (!event)
    return 0;
  struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
  get_dentry_path_str(dentry, event->filename);
  event->event = FILE_DELETED;
  event->timestamp = bpf_ktime_get_ns();
  event->pid = tgid;

  LOG_DEBUG("unlink %s", event->filename);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct event_t));
  return 0;
}

SEC("kprobe/security_file_open")
int security_file_open(struct pt_regs *ctx) {
  pid_t tgid = interesting_tgid();
  if (tgid < 0)
    return 0;

  u32 key = 0;
  struct event_t *event = bpf_map_lookup_elem(&eventmem, &key);
  if (!event)
    return 0;
  struct file *file = (struct file *)PT_REGS_PARM1(ctx);
  struct path path = BPF_CORE_READ(file, f_path);
  get_path_str(&path, event->filename);
  event->event = FILE_OPENED;
  event->timestamp = bpf_ktime_get_ns();
  event->pid = tgid;
  event->flags = BPF_CORE_READ(file, f_flags);

  LOG_DEBUG("open %s", event->filename);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct event_t));
  return 0;
}
