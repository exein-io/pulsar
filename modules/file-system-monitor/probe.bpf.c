// SPDX-License-Identifier: GPL-2.0
#include "buffer.bpf.h"
#include "common.bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define FILE_CREATED 0
#define FILE_DELETED 1
#define DIR_CREATED 2
#define DIR_DELETED 3
#define FILE_OPENED 4
#define FILE_LINK 5
#define FILE_RENAME 6
#define MAX_PATH_COMPONENTS 10

struct file_opened_event {
  struct buffer_index filename;
  int flags;
};

struct file_link_event {
  struct buffer_index source;
  struct buffer_index destination;
  bool hard_link;
};

struct file_rename_event {
  struct buffer_index source;
  struct buffer_index destination;
};

struct event_t {
  u64 timestamp;
  pid_t pid;
  u32 event_type;
  union {
    struct buffer_index created;
    struct buffer_index deleted;
    struct buffer_index dir_created;
    struct buffer_index dir_deleted;
    struct file_opened_event opened;
    struct file_link_event link;
    struct file_rename_event rename;
  };
  struct buffer buffer;
};

struct bpf_map_def_aya SEC("maps/event") eventmem = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct event_t),
    .max_entries = 1,
};

// used to send events to userspace
struct bpf_map_def_aya SEC("maps/events") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 0,
};

static struct event_t *init_event(int event_type) {
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
  event->buffer.len = 0;
  return event;
}

// get_path_str was copied and adapted from Tracee
// Returns the length of the copied entry
static void get_path_str(struct dentry *dentry, struct path *path,
                         struct buffer *buffer, struct buffer_index *index) {
  char slash = '/';
  int zero = 0;
  struct vfsmount *vfsmnt = BPF_CORE_READ(path, mnt);
  struct mount *mnt_p = container_of(vfsmnt, struct mount, mnt);
  struct mount *mnt_parent_p = BPF_CORE_READ(mnt_p, mnt_parent);

  struct qstr components[MAX_PATH_COMPONENTS];
#pragma unroll
  for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
    components[i].len = 0;
    components[i].name = 0;
  }

  int count = 0;
#pragma unroll
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
        bpf_core_read(&dentry, sizeof(struct dentry *), &mnt_p->mnt_mountpoint);
        bpf_core_read(&mnt_p, sizeof(struct mount *), &mnt_p->mnt_parent);
        bpf_core_read(&mnt_parent_p, sizeof(struct mount *),
                      &mnt_p->mnt_parent);
        vfsmnt = &mnt_p->mnt;
        continue;
      }
      // Global root - path fully parsed
      break;
    }
    // Add this dentry name to path
    components[i] = BPF_CORE_READ(dentry, d_name);
    dentry = d_parent;
    count++;
  }

  // copy compoenents
  buffer_index_init(buffer, index);
#pragma unroll
  for (int i = MAX_PATH_COMPONENTS; i >= 0; i--) {
    if (i >= count)
      continue;
    if (components[i].len == 0)
      continue;
    buffer_append_str(buffer, index, &slash, 1);
    buffer_append_str(buffer, index, (char *)components[i].name,
                      components[i].len);
  }
  return;
}

static __always_inline void output_event(void *ctx, struct event_t *event) {
  unsigned int len = sizeof(struct event_t) - BUFFER_MAX + event->buffer.len;
  if (len > 0 && len <= sizeof(struct event_t)) {
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                          len & (BUFFER_MAX - 1));
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
  get_path_str(dentry, dir, &event->buffer, &event->created);
  output_event(ctx, event);
}

PULSAR_LSM_HOOK(path_unlink, struct path *, dir, struct dentry *, dentry);
static __always_inline void on_path_unlink(void *ctx, struct path *dir,
                                           struct dentry *dentry) {
  struct event_t *event = init_event(FILE_DELETED);
  if (!event)
    return;
  get_path_str(dentry, dir, &event->buffer, &event->deleted);
  output_event(ctx, event);
}

PULSAR_LSM_HOOK(file_open, struct file *, file);
static __always_inline void on_file_open(void *ctx, struct file *file) {
  struct event_t *event = init_event(FILE_OPENED);
  if (!event)
    return;
  struct path path = BPF_CORE_READ(file, f_path);
  get_path_str(path.dentry, &path, &event->buffer, &event->opened.filename);
  event->opened.flags = BPF_CORE_READ(file, f_flags);
  output_event(ctx, event);
}

PULSAR_LSM_HOOK(path_link, struct dentry *, old_dentry, struct path *, new_dir,
                struct dentry *, new_dentry);
static __always_inline void on_path_link(void *ctx, struct dentry *old_dentry,
                                         struct path *new_dir,
                                         struct dentry *new_dentry) {
  struct event_t *event = init_event(FILE_LINK);
  if (!event)
    return;
  get_path_str(new_dentry, new_dir, &event->buffer, &event->link.source);
  get_path_str(old_dentry, new_dir, &event->buffer, &event->link.destination);
  event->link.hard_link = true;
  //  event->link.destination);
  output_event(ctx, event);
}

PULSAR_LSM_HOOK(path_symlink, struct path *, dir, struct dentry *, dentry,
                char *, old_name);
static __always_inline void on_path_symlink(void *ctx, struct path *dir,
                                            struct dentry *dentry,
                                            char *old_name) {
  struct event_t *event = init_event(FILE_LINK);
  if (!event)
    return;
  get_path_str(dentry, dir, &event->buffer, &event->link.source);
  buffer_index_init(&event->buffer, &event->link.destination);
  buffer_append_str(&event->buffer, &event->link.destination, old_name,
                    BUFFER_MAX);
  event->link.hard_link = false;
  output_event(ctx, event);
}

PULSAR_LSM_HOOK(path_mkdir, struct path *, dir, struct dentry *, dentry,
                umode_t, mode);
static __always_inline void on_path_mkdir(void *ctx, struct path *dir,
                                          struct dentry *dentry, umode_t mode) {
  struct event_t *event = init_event(DIR_CREATED);
  if (!event)
    return;
  get_path_str(dentry, dir, &event->buffer, &event->dir_created);
  output_event(ctx, event);
}

PULSAR_LSM_HOOK(path_rmdir, struct path *, dir, struct dentry *, dentry);
static __always_inline void on_path_rmdir(void *ctx, struct path *dir,
                                          struct dentry *dentry) {
  struct event_t *event = init_event(DIR_DELETED);
  if (!event)
    return;
  get_path_str(dentry, dir, &event->buffer, &event->dir_deleted);
  event->event_type = DIR_DELETED;
  output_event(ctx, event);
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
  get_path_str(old_dentry, old_dir, &event->buffer, &event->rename.source);
  get_path_str(new_dentry, new_dir, &event->buffer, &event->rename.destination);
  output_event(ctx, event);
}
