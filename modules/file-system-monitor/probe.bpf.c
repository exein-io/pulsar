// SPDX-License-Identifier: GPL-2.0
#include "common.bpf.h"

char LICENSE[] SEC("license") = "GPL";

int my_pid = 0;

#define FILE_CREATED 0
#define FILE_DELETED 1
#define FILE_OPENED 2
#define FILE_LINK 3
#define NAME_MAX 1024
#define MAX_PATH_COMPONENTS 20

struct file_opened_event {
  char filename[NAME_MAX];
  int flags;
};

struct file_link_event {
  char source[NAME_MAX];
  char destination[NAME_MAX];
  bool hard_link;
};

struct event_t {
  u64 timestamp;
  pid_t pid;
  u32 event_type;
  union {
    char created[NAME_MAX];
    char deleted[NAME_MAX];
    struct file_opened_event opened;
    struct file_link_event link;
  };
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
// vfsmnt is used to get the path of the mount point. If NULL, we can only get
// the path up to the mount point.
static __always_inline void get_path_str(struct dentry *dentry,
                                         struct vfsmount *vfsmnt,
                                         char buf[NAME_MAX]) {
  char slash = '/';
  int zero = 0;
  struct mount *mnt_parent_p = NULL;
  struct mount *mnt_p = NULL;
  if (vfsmnt) {
    mnt_p = container_of(vfsmnt, struct mount, mnt);
    bpf_probe_read_kernel(&mnt_parent_p, sizeof(struct mount *),
                          &mnt_p->mnt_parent);
  }

  u32 buf_off = (NAME_MAX >> 1);

  if (buf == NULL)
    return;

#pragma unroll
  for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
    struct dentry *mnt_root = NULL;
    if (vfsmnt) {
      mnt_root = (struct dentry *)BPF_CORE_READ(vfsmnt, mnt_root);
    }
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
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    unsigned int len = (d_name.len + 1) & (NAME_MAX - 1);
    unsigned int off = buf_off - len;

    // Is string buffer big enough for dentry name?
    int sz = 0;
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

static __always_inline void on_inode_create(void *ctx, struct inode *dir,
                                            struct dentry *dentry,
                                            umode_t mode) {
  pid_t tgid = interesting_tgid();
  if (tgid < 0)
    return;

  u32 key = 0;
  struct event_t *event = bpf_map_lookup_elem(&eventmem, &key);
  if (!event)
    return;

  get_path_str(dentry, NULL, event->created);
  event->event_type = FILE_CREATED;
  event->timestamp = bpf_ktime_get_ns();
  event->pid = tgid;

  LOG_DEBUG("create %s", event->created);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct event_t));
}

static __always_inline void on_path_unlink(void *ctx, struct path *dir,
                                            struct dentry *dentry) {
  pid_t tgid = interesting_tgid();
  if (tgid < 0)
    return;

  u32 key = 0;
  struct event_t *event = bpf_map_lookup_elem(&eventmem, &key);
  if (!event)
    return;
  struct vfsmount *vfsmnt = BPF_CORE_READ(dir, mnt);
  get_path_str(dentry, vfsmnt, event->deleted);
  event->event_type = FILE_DELETED;
  event->timestamp = bpf_ktime_get_ns();
  event->pid = tgid;

  LOG_DEBUG("unlink %s", event->deleted);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct event_t));
  return;
}

void __always_inline on_file_open(void *ctx, struct file *file) {
  pid_t tgid = interesting_tgid();
  if (tgid < 0)
    return;

  u32 key = 0;
  struct event_t *event = bpf_map_lookup_elem(&eventmem, &key);
  if (!event)
    return;
  struct path path = BPF_CORE_READ(file, f_path);
  get_path_str(path.dentry, path.mnt, event->opened.filename);
  event->event_type = FILE_OPENED;
  event->timestamp = bpf_ktime_get_ns();
  event->pid = tgid;
  event->opened.flags = BPF_CORE_READ(file, f_flags);

  LOG_DEBUG("open %s", event->opened.filename);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct event_t));
  return;
}

void __always_inline on_file_link(void *ctx, struct dentry *old_dentry,
                                  struct path *new_dir,
                                  struct dentry *new_dentry) {
  pid_t tgid = interesting_tgid();
  if (tgid < 0)
    return;

  u32 key = 0;
  struct event_t *event = bpf_map_lookup_elem(&eventmem, &key);
  if (!event)
    return;

  struct vfsmount *vfsmnt = BPF_CORE_READ(new_dir, mnt);
  get_path_str(new_dentry, vfsmnt, event->link.source);
  get_path_str(old_dentry, vfsmnt, event->link.destination);
  event->event_type = FILE_LINK;
  event->timestamp = bpf_ktime_get_ns();
  event->pid = tgid;
  event->link.hard_link = true;

  LOG_DEBUG("symlink %s -> %s", event->link.source, event->link.destination);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct event_t));
  return;
}

void __always_inline on_file_symlink(void *ctx, struct path *dir,
                                     struct dentry *dentry, char *old_name) {
  pid_t tgid = interesting_tgid();
  if (tgid < 0)
    return;

  u32 key = 0;
  struct event_t *event = bpf_map_lookup_elem(&eventmem, &key);
  if (!event)
    return;

  struct vfsmount *vfsmnt = BPF_CORE_READ(dir, mnt);
  get_path_str(dentry, vfsmnt, event->link.source);
  bpf_probe_read_kernel_str(event->link.destination, NAME_MAX, old_name);
  event->event_type = FILE_LINK;
  event->timestamp = bpf_ktime_get_ns();
  event->pid = tgid;
  event->link.hard_link = false;

  LOG_DEBUG("symlink %s -> %s", event->link.source, event->link.destination);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct event_t));
  return;
}

/// LSM hook points

SEC("lsm/inode_create")
int BPF_PROG(inode_create, struct inode *dir, struct dentry *dentry,
             umode_t mode, int ret) {
  on_inode_create(ctx, dir, dentry, mode);
  return ret;
}

SEC("lsm/path_unlink")
int BPF_PROG(path_unlink, struct path *dir, struct dentry *dentry, int ret) {
  on_path_unlink(ctx, dir, dentry);
  return ret;
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file, int ret) {
  on_file_open(ctx, file);
  return ret;
}

SEC("lsm/path_link")
int BPF_PROG(path_link, struct dentry *old_dentry, struct path *new_dir,
             struct dentry *new_dentry, int ret) {
  on_file_link(ctx, old_dentry, new_dir, new_dentry);
  return ret;
}

SEC("lsm/path_symlink")
int BPF_PROG(path_symlink, struct path *dir, struct dentry *dentry,
             char *old_name, int ret) {
  on_file_symlink(ctx, dir, dentry, old_name);
  return ret;
}

/// Fallback kprobes

SEC("kprobe/security_inode_create")
int BPF_KPROBE(security_inode_create, struct inode *dir, struct dentry *dentry,
               umode_t mode) {
  on_inode_create(ctx, dir, dentry, mode);
  return 0;
}

SEC("kprobe/security_path_unlink")
int BPF_KPROBE(security_path_unlink, struct path *dir,
               struct dentry *dentry) {
  on_path_unlink(ctx, dir, dentry);
  return 0;
}

SEC("kprobe/security_file_open")
int BPF_KPROBE(security_file_open, struct file *file) {
  on_file_open(ctx, file);
  return 0;
}

SEC("kprobe/security_path_link")
int BPF_PROG(security_path_link, struct dentry *old_dentry,
             struct path *new_dir, struct dentry *new_dentry) {
  on_file_link(ctx, old_dentry, new_dir, new_dentry);
  return 0;
}

SEC("kprobe/security_path_symlink")
int BPF_PROG(security_path_symlink, struct path *dir, struct dentry *dentry,
             char *old_name) {
  on_file_symlink(ctx, dir, dentry, old_name);
  return 0;
}
