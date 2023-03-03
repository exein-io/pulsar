// SPDX-License-Identifier: GPL-2.0
#include "buffer.bpf.h"
#include "common.bpf.h"
#include "get_path.bpf.h"
char LICENSE[] SEC("license") = "GPL";

#define FILE_CREATED 0
#define FILE_DELETED 1
#define DIR_CREATED 2
#define DIR_DELETED 3
#define FILE_OPENED 4
#define FILE_LINK 5
#define FILE_RENAME 6

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

OUTPUT_MAP(events, fs_event, {
  struct buffer_index created;
  struct buffer_index deleted;
  struct buffer_index dir_created;
  struct buffer_index dir_deleted;
  struct file_opened_event opened;
  struct file_link_event link;
  struct file_rename_event rename;
});

PULSAR_LSM_HOOK(path_mknod, struct path *, dir, struct dentry *, dentry,
                umode_t, mode, unsigned int, dev);
static __always_inline void on_path_mknod(void *ctx, struct path *dir,
                                          struct dentry *dentry, umode_t mode,
                                          unsigned int dev) {
  struct fs_event *event = fs_event_init(FILE_CREATED);
  if (!event)
    return;
  get_path_str(dentry, dir, &event->buffer, &event->created);
  output_event(ctx, &events, event, sizeof(struct fs_event), event->buffer.len);
}

PULSAR_LSM_HOOK(path_unlink, struct path *, dir, struct dentry *, dentry);
static __always_inline void on_path_unlink(void *ctx, struct path *dir,
                                           struct dentry *dentry) {
  struct fs_event *event = fs_event_init(FILE_DELETED);
  if (!event)
    return;
  get_path_str(dentry, dir, &event->buffer, &event->deleted);
  output_event(ctx, &events, event, sizeof(struct fs_event), event->buffer.len);
}

PULSAR_LSM_HOOK(file_open, struct file *, file);
static __always_inline void on_file_open(void *ctx, struct file *file) {
  struct fs_event *event = fs_event_init(FILE_OPENED);
  if (!event)
    return;
  struct path path = BPF_CORE_READ(file, f_path);
  get_path_str(path.dentry, &path, &event->buffer, &event->opened.filename);
  event->opened.flags = BPF_CORE_READ(file, f_flags);
  output_event(ctx, &events, event, sizeof(struct fs_event), event->buffer.len);
}

PULSAR_LSM_HOOK(path_link, struct dentry *, old_dentry, struct path *, new_dir,
                struct dentry *, new_dentry);
static __always_inline void on_path_link(void *ctx, struct dentry *old_dentry,
                                         struct path *new_dir,
                                         struct dentry *new_dentry) {
  struct fs_event *event = fs_event_init(FILE_LINK);
  if (!event)
    return;
  get_path_str(new_dentry, new_dir, &event->buffer, &event->link.source);
  get_path_str(old_dentry, new_dir, &event->buffer, &event->link.destination);
  event->link.hard_link = true;
  output_event(ctx, &events, event, sizeof(struct fs_event), event->buffer.len);
}

PULSAR_LSM_HOOK(path_symlink, struct path *, dir, struct dentry *, dentry,
                char *, old_name);
static __always_inline void on_path_symlink(void *ctx, struct path *dir,
                                            struct dentry *dentry,
                                            char *old_name) {
  struct fs_event *event = fs_event_init(FILE_LINK);
  if (!event)
    return;
  get_path_str(dentry, dir, &event->buffer, &event->link.source);
  buffer_index_init(&event->buffer, &event->link.destination);
  buffer_append_str(&event->buffer, &event->link.destination, old_name,
                    BUFFER_MAX);
  event->link.hard_link = false;
  output_event(ctx, &events, event, sizeof(struct fs_event), event->buffer.len);
}

PULSAR_LSM_HOOK(path_mkdir, struct path *, dir, struct dentry *, dentry,
                umode_t, mode);
static __always_inline void on_path_mkdir(void *ctx, struct path *dir,
                                          struct dentry *dentry, umode_t mode) {
  struct fs_event *event = fs_event_init(DIR_CREATED);
  if (!event)
    return;
  get_path_str(dentry, dir, &event->buffer, &event->dir_created);
  output_event(ctx, &events, event, sizeof(struct fs_event), event->buffer.len);
}

PULSAR_LSM_HOOK(path_rmdir, struct path *, dir, struct dentry *, dentry);
static __always_inline void on_path_rmdir(void *ctx, struct path *dir,
                                          struct dentry *dentry) {
  struct fs_event *event = fs_event_init(DIR_DELETED);
  if (!event)
    return;
  get_path_str(dentry, dir, &event->buffer, &event->dir_deleted);
  output_event(ctx, &events, event, sizeof(struct fs_event), event->buffer.len);
}

PULSAR_LSM_HOOK(path_rename, struct path *, old_dir, struct dentry *,
                old_dentry, struct path *, new_dir, struct dentry *,
                new_dentry);
static __always_inline void on_path_rename(void *ctx, struct path *old_dir,
                                           struct dentry *old_dentry,
                                           struct path *new_dir,
                                           struct dentry *new_dentry) {
  struct fs_event *event = fs_event_init(FILE_RENAME);
  if (!event)
    return;
  get_path_str(old_dentry, old_dir, &event->buffer, &event->rename.source);
  get_path_str(new_dentry, new_dir, &event->buffer, &event->rename.destination);
  output_event(ctx, &events, event, sizeof(struct fs_event), event->buffer.len);
}
