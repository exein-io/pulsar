// SPDX-License-Identifier: GPL-2.0
#include "buffer.bpf.h"
#include "common.bpf.h"
#include "output.bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define FILE_CREATED 0
#define FILE_DELETED 1
#define DIR_CREATED 2
#define DIR_DELETED 3
#define FILE_OPENED 4
#define FILE_LINK 5
#define FILE_RENAME 6
#define MAX_PATH_COMPONENTS 20

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

// Append to buffer a slash and the path component pointed at by name.
// This is needed to satisfy the verifier.
static void append_path_component(struct buffer *buffer,
                                  struct buffer_index *index,
                                  const unsigned char *name, int len) {
  if (len == 0)
    return;
  if (name == 0)
    return;
  buffer_append_str(buffer, index, "/", 1);
  buffer_append_str(buffer, index, (char *)name, len);
}

struct callback_ctx {
  struct dentry *dentry;
  struct vfsmount *vfsmnt;
  struct mount *mnt_p;
  struct mount *mnt_parent_p;
  // Output components names and lens
  const unsigned char *component_name[MAX_PATH_COMPONENTS];
  u32 component_len[MAX_PATH_COMPONENTS];
};

static long callback_fn(u32 i, void *void_ctx) {
  struct callback_ctx *ctx = void_ctx;
  if (!ctx)
    return 1;
  struct dentry *mnt_root =
      (struct dentry *)BPF_CORE_READ(ctx->vfsmnt, mnt_root);
  struct dentry *d_parent = BPF_CORE_READ(ctx->dentry, d_parent);
  if (ctx->dentry == mnt_root || ctx->dentry == d_parent) {
    if (ctx->dentry != mnt_root) {
      // We reached root, but not mount root - escaped?
      return 1;
    }
    if (ctx->mnt_p != ctx->mnt_parent_p) {
      // We reached root, but not global root - continue with mount point path
      bpf_core_read(&ctx->dentry, sizeof(struct dentry *),
                    &ctx->mnt_p->mnt_mountpoint);
      bpf_core_read(&ctx->mnt_p, sizeof(struct mount *),
                    &ctx->mnt_p->mnt_parent);
      bpf_core_read(&ctx->mnt_parent_p, sizeof(struct mount *),
                    &ctx->mnt_p->mnt_parent);
      ctx->vfsmnt = &ctx->mnt_p->mnt;
      return 0;
    }
    // Global root - path fully parsed
    return 1;
  }
  // Add this dentry name to path
  struct qstr entry = BPF_CORE_READ(ctx->dentry, d_name);
  if (i < MAX_PATH_COMPONENTS) {
    ctx->component_len[i] = entry.len;
    ctx->component_name[i] = entry.name;
  }
  ctx->dentry = d_parent;
  return 0;
}

// Copy of callback_fn used in bpf_loop. This is identical to the other one.
// For some reason, calling the same function would result in the verifier
// messing up and failing with a "too many instructions to verify" error.
static long callback_fn_loop(u32 i, void *void_ctx) {
  struct callback_ctx *ctx = void_ctx;
  if (!ctx)
    return 1;
  struct dentry *mnt_root =
      (struct dentry *)BPF_CORE_READ(ctx->vfsmnt, mnt_root);
  struct dentry *d_parent = BPF_CORE_READ(ctx->dentry, d_parent);
  if (ctx->dentry == mnt_root || ctx->dentry == d_parent) {
    if (ctx->dentry != mnt_root) {
      // We reached root, but not mount root - escaped?
      return 1;
    }
    if (ctx->mnt_p != ctx->mnt_parent_p) {
      // We reached root, but not global root - continue with mount point path
      bpf_core_read(&ctx->dentry, sizeof(struct dentry *),
                    &ctx->mnt_p->mnt_mountpoint);
      bpf_core_read(&ctx->mnt_p, sizeof(struct mount *),
                    &ctx->mnt_p->mnt_parent);
      bpf_core_read(&ctx->mnt_parent_p, sizeof(struct mount *),
                    &ctx->mnt_p->mnt_parent);
      ctx->vfsmnt = &ctx->mnt_p->mnt;
      return 0;
    }
    // Global root - path fully parsed
    return 1;
  }
  // Add this dentry name to path
  struct qstr entry = BPF_CORE_READ(ctx->dentry, d_name);
  if (i < MAX_PATH_COMPONENTS) {
    ctx->component_len[i] = entry.len;
    ctx->component_name[i] = entry.name;
  }
  ctx->dentry = d_parent;
  return 0;
}

// get_path_str was copied and adapted from Tracee
// Returns the length of the copied entry
static void get_path_str(struct dentry *dentry, struct path *path,
                         struct buffer *buffer, struct buffer_index *index) {
  struct callback_ctx ctx;
  ctx.dentry = dentry;
  ctx.vfsmnt = BPF_CORE_READ(path, mnt);
  ctx.mnt_p = container_of(ctx.vfsmnt, struct mount, mnt);
  ctx.mnt_parent_p = BPF_CORE_READ(ctx.mnt_p, mnt_parent);
  __builtin_memset(ctx.component_name, 0, sizeof(ctx.component_name));
  __builtin_memset(ctx.component_len, 0, sizeof(ctx.component_len));

  if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 17, 0)) {
    bpf_loop(MAX_PATH_COMPONENTS, callback_fn_loop, &ctx, 0);
  } else {
#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
      if (callback_fn(i, &ctx) == 1)
        break;
    }
  }

  // copy components
  buffer_index_init(buffer, index);
  for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
    int t = MAX_PATH_COMPONENTS - i - 1;
    append_path_component(buffer, index, ctx.component_name[t],
                          ctx.component_len[t]);
  }
  return;
}

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
