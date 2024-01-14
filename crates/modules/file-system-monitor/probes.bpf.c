// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"

#include "bpf/bpf_helpers.h"
#include "buffer.bpf.h"
#include "common.bpf.h"
#include "get_path.bpf.h"
#include "interest_tracking.bpf.h"
char LICENSE[] SEC("license") = "GPL v2";

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

GLOBAL_INTEREST_MAP_DECLARATION;

OUTPUT_MAP(fs_event, {
  struct buffer_index created;
  struct buffer_index deleted;
  struct buffer_index dir_created;
  struct buffer_index dir_deleted;
  struct file_opened_event opened;
  struct file_link_event link;
  struct file_rename_event rename;
});

// A struct path contains a dentry and it's mount point.
// Most LSM methods take the dentry of the target file and its parent folder
// struct path. This utility function returns the struct path of the dentry,
// by combining it with the struct vfsmount extracted by the parent dentry.
static __always_inline struct path make_path(struct dentry *target_dentry,
                                             struct path *parent_path) {
  struct path target_path = {
      .dentry = target_dentry,
      .mnt = BPF_CORE_READ(parent_path, mnt),
  };
  return target_path;
}

PULSAR_LSM_HOOK(path_mknod, struct path *, dir, struct dentry *, dentry,
                umode_t, mode, unsigned int, dev);
static __always_inline void on_path_mknod(void *ctx, struct path *dir,
                                          struct dentry *dentry, umode_t mode,
                                          unsigned int dev) {
  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return;
  struct fs_event *event = init_fs_event(FILE_CREATED, tgid);
  if (!event)
    return;
  struct path path = make_path(dentry, dir);
  get_path_str(&path, &event->buffer, &event->created);
  output_fs_event(ctx, event);
}

PULSAR_LSM_HOOK(path_unlink, struct path *, dir, struct dentry *, dentry);
static __always_inline void on_path_unlink(void *ctx, struct path *dir,
                                           struct dentry *dentry) {
  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return;
  struct fs_event *event = init_fs_event(FILE_DELETED, tgid);
  if (!event)
    return;
  struct path path = make_path(dentry, dir);
  get_path_str(&path, &event->buffer, &event->deleted);
  output_fs_event(ctx, event);
}

PULSAR_LSM_HOOK(file_open, struct file *, file);
static __always_inline void on_file_open(void *ctx, struct file *file) {
  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return;
  unsigned int flags = BPF_CORE_READ(file, f_flags);
  // This bit is present in file flags during the second, duplicate trigger of
  // the `file_open` hook when running inside container. When the bit is
  // present, just stop the program.
  if (flags & 01000000)
    return;
  struct fs_event *event = init_fs_event(FILE_OPENED, tgid);
  if (!event)
    return;
  struct path path = BPF_CORE_READ(file, f_path);
  get_path_str(&path, &event->buffer, &event->opened.filename);
  event->opened.flags = BPF_CORE_READ(file, f_flags);
  output_fs_event(ctx, event);
}

PULSAR_LSM_HOOK(path_link, struct dentry *, old_dentry, struct path *, new_dir,
                struct dentry *, new_dentry);
static __always_inline void on_path_link(void *ctx, struct dentry *old_dentry,
                                         struct path *new_dir,
                                         struct dentry *new_dentry) {
  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return;
  struct fs_event *event = init_fs_event(FILE_LINK, tgid);
  if (!event)
    return;
  struct path source = make_path(new_dentry, new_dir);
  get_path_str(&source, &event->buffer, &event->link.source);
  struct path destination = make_path(old_dentry, new_dir);
  get_path_str(&destination, &event->buffer, &event->link.destination);
  event->link.hard_link = true;
  output_fs_event(ctx, event);
}

PULSAR_LSM_HOOK(path_symlink, struct path *, dir, struct dentry *, dentry,
                char *, old_name);
static __always_inline void on_path_symlink(void *ctx, struct path *dir,
                                            struct dentry *dentry,
                                            char *old_name) {
  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return;
  struct fs_event *event = init_fs_event(FILE_LINK, tgid);
  if (!event)
    return;
  struct path path = make_path(dentry, dir);
  get_path_str(&path, &event->buffer, &event->link.source);
  buffer_index_init(&event->buffer, &event->link.destination);
  buffer_append_str(&event->buffer, &event->link.destination, old_name,
                    BUFFER_MAX);
  event->link.hard_link = false;
  output_fs_event(ctx, event);
}

PULSAR_LSM_HOOK(path_mkdir, struct path *, dir, struct dentry *, dentry,
                umode_t, mode);
static __always_inline void on_path_mkdir(void *ctx, struct path *dir,
                                          struct dentry *dentry, umode_t mode) {
  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return;
  struct fs_event *event = init_fs_event(DIR_CREATED, tgid);
  if (!event)
    return;
  struct path path = make_path(dentry, dir);
  get_path_str(&path, &event->buffer, &event->dir_created);
  output_fs_event(ctx, event);
}

PULSAR_LSM_HOOK(path_rmdir, struct path *, dir, struct dentry *, dentry);
static __always_inline void on_path_rmdir(void *ctx, struct path *dir,
                                          struct dentry *dentry) {
  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return;
  struct fs_event *event = init_fs_event(DIR_DELETED, tgid);
  if (!event)
    return;
  struct path path = make_path(dentry, dir);
  get_path_str(&path, &event->buffer, &event->dir_deleted);
  output_fs_event(ctx, event);
}

PULSAR_LSM_HOOK(path_rename, struct path *, old_dir, struct dentry *,
                old_dentry, struct path *, new_dir, struct dentry *,
                new_dentry);
static __always_inline void on_path_rename(void *ctx, struct path *old_dir,
                                           struct dentry *old_dentry,
                                           struct path *new_dir,
                                           struct dentry *new_dentry) {
  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return;
  struct fs_event *event = init_fs_event(FILE_RENAME, tgid);
  if (!event)
    return;
  struct path source = make_path(old_dentry, old_dir);
  struct path destination = make_path(new_dentry, new_dir);
  get_path_str(&source, &event->buffer, &event->rename.source);
  get_path_str(&destination, &event->buffer, &event->rename.destination);
  output_fs_event(ctx, event);
}
