// SPDX-License-Identifier: GPL-2.0
#include "common.bpf.h"

char LICENSE[] SEC("license") = "GPL";

int my_pid = 0;

#define FILE_CREATED 0
#define FILE_DELETED 1
#define DIR_CREATED 2
#define DIR_DELETED 3
#define FILE_OPENED 4
#define FILE_LINK 5
#define FILE_RENAME 6
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

struct file_rename_event {
  char source[NAME_MAX];
  char destination[NAME_MAX];
};

struct event_t {
  u64 timestamp;
  pid_t pid;
  u32 event_type;
  union {
    char created[NAME_MAX];
    char deleted[NAME_MAX];
    char dir_created[NAME_MAX];
    char dir_deleted[NAME_MAX];
    struct file_opened_event opened;
    struct file_link_event link;
    struct file_rename_event rename;
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

static __always_inline struct event_t *init_event(int event_type) {
  pid_t tgid = interesting_tgid();
  if (tgid < 0)
    return NULL;

  u32 key = 0;
  struct event_t *event = bpf_map_lookup_elem(&eventmem, &key);
  if (!event)
    return NULL;

  event->event_type = event_type;
  event->timestamp = bpf_ktime_get_ns();
  event->pid = tgid;

  return event;
}

// get_path_str was copied and adapted from Tracee
static __always_inline void
get_path_str(struct dentry *dentry, struct path *path, char buf[NAME_MAX]) {
  char slash = '/';
  int zero = 0;
  struct vfsmount *vfsmnt = BPF_CORE_READ(path, mnt);
  struct mount *mnt_p = container_of(vfsmnt, struct mount, mnt);
  struct mount *mnt_parent_p = BPF_CORE_READ(mnt_p, mnt_parent);

  u32 buf_off = (NAME_MAX >> 1);

  if (buf == NULL)
    return;

  for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
    struct dentry *mnt_root = NULL;
    mnt_root = (struct dentry *)BPF_CORE_READ(vfsmnt, mnt_root);
    struct dentry *d_parent = BPF_CORE_READ(dentry, d_parent);
    if (dentry == mnt_root || dentry == d_parent) {
      if (dentry != mnt_root) {
        // We reached root, but not mount root - escaped?
        break;
      }
      if (mnt_p != mnt_parent_p) {
        // We reached root, but not global root - continue with mount point path
        bpf_core_read(&dentry, sizeof(struct dentry *),
                              &mnt_p->mnt_mountpoint);
        bpf_core_read(&mnt_p, sizeof(struct mount *),
                              &mnt_p->mnt_parent);
        bpf_core_read(&mnt_parent_p, sizeof(struct mount *),
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
      sz = bpf_core_read_str(&(buf[off & ((NAME_MAX >> 1) - 1)]), len,
                                     (void *)d_name.name);
    } else
      break;
    if (sz > 1) {
      buf_off -= 1; // remove null byte termination with slash sign
      bpf_core_read(&(buf[buf_off & (NAME_MAX - 1)]), 1, &slash);
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
    bpf_core_read_str(&(buf[0]), NAME_MAX, (void *)d_name.name);
  } else {
    // Add leading slash
    buf_off -= 1;
    bpf_core_read(&(buf[buf_off & (NAME_MAX - 1)]), 1, &slash);
    // Null terminate the path string
    bpf_core_read(&(buf[(NAME_MAX >> 1) - 1]), 1, &zero);

    // Copy string to the start
    int total_len = NAME_MAX - buf_off;
    bpf_core_read(buf, total_len & (NAME_MAX - 1),
                          buf + (buf_off & NAME_MAX - 1));
  }
}

PULSAR_LSM_HOOK(path_mknod, struct path *, dir, struct dentry *, dentry,
                umode_t, mode, unsigned int, dev);
static __always_inline void on_path_mknod(void *ctx, struct path *dir,
                                          struct dentry *dentry, umode_t mode,
                                          unsigned int dev) {
  struct event_t *event = init_event(FILE_CREATED);
  if (!event)
    return;
  get_path_str(dentry, dir, event->created);
  LOG_DEBUG("create %s", event->created);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct event_t));
}

PULSAR_LSM_HOOK(path_unlink, struct path *, dir, struct dentry *, dentry);
static __always_inline void on_path_unlink(void *ctx, struct path *dir,
                                           struct dentry *dentry) {
  struct event_t *event = init_event(FILE_DELETED);
  if (!event)
    return;
  get_path_str(dentry, dir, event->deleted);
  LOG_DEBUG("unlink %s", event->deleted);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct event_t));
}

PULSAR_LSM_HOOK(file_open, struct file *, file);
static __always_inline void on_file_open(void *ctx, struct file *file) {
  struct event_t *event = init_event(FILE_OPENED);
  if (!event)
    return;
  struct path path = BPF_CORE_READ(file, f_path);
  get_path_str(path.dentry, &path, event->opened.filename);
  event->opened.flags = BPF_CORE_READ(file, f_flags);
  LOG_DEBUG("open %s", event->opened.filename);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct event_t));
}

PULSAR_LSM_HOOK(path_link, struct dentry *, old_dentry, struct path *, new_dir,
                struct dentry *, new_dentry);
static __always_inline void on_path_link(void *ctx, struct dentry *old_dentry,
                                         struct path *new_dir,
                                         struct dentry *new_dentry) {
  struct event_t *event = init_event(FILE_LINK);
  if (!event)
    return;
  get_path_str(new_dentry, new_dir, event->link.source);
  get_path_str(old_dentry, new_dir, event->link.destination);
  event->link.hard_link = true;
  LOG_DEBUG("hardlink %s -> %s", event->link.source, event->link.destination);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct event_t));
}

PULSAR_LSM_HOOK(path_symlink, struct path *, dir, struct dentry *, dentry,
                char *, old_name);
static __always_inline void on_path_symlink(void *ctx, struct path *dir,
                                            struct dentry *dentry,
                                            char *old_name) {
  struct event_t *event = init_event(FILE_LINK);
  if (!event)
    return;
  get_path_str(dentry, dir, event->link.source);
  bpf_core_read_str(event->link.destination, NAME_MAX, old_name);
  event->link.hard_link = false;
  LOG_DEBUG("symlink %s -> %s", event->link.source, event->link.destination);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct event_t));
}

PULSAR_LSM_HOOK(path_mkdir, struct path *, dir, struct dentry *, dentry,
                umode_t, mode);
static __always_inline void on_path_mkdir(void *ctx, struct path *dir,
                                          struct dentry *dentry, umode_t mode) {
  struct event_t *event = init_event(DIR_CREATED);
  if (!event)
    return;
  get_path_str(dentry, dir, event->dir_created);
  LOG_DEBUG("mkdir %s", event->dir_created);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct event_t));
}

PULSAR_LSM_HOOK(path_rmdir, struct path *, dir, struct dentry *, dentry);
static __always_inline void on_path_rmdir(void *ctx, struct path *dir,
                                          struct dentry *dentry) {
  struct event_t *event = init_event(DIR_DELETED);
  if (!event)
    return;
  get_path_str(dentry, dir, event->dir_deleted);
  event->event_type = DIR_DELETED;
  LOG_DEBUG("mkdir %s", event->dir_deleted);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct event_t));
}

PULSAR_LSM_HOOK(path_rename, struct path *, old_dir, struct dentry *,
                old_dentry, struct path *, new_dir, struct dentry *,
                new_dentry);
static __always_inline void on_path_rename(void *ctx, struct path *old_dir,
                                           struct dentry *old_dentry,
                                           struct path *new_dir,
                                           struct dentry *new_dentry) {
  struct event_t *event = init_event(FILE_RENAME);
  if (!event)
    return;
  get_path_str(old_dentry, old_dir, event->rename.source);
  get_path_str(new_dentry, new_dir, event->rename.destination);
  LOG_DEBUG("rename %s -> %s", event->rename.source, event->rename.destination);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct event_t));
}
