#pragma once
#include "common.bpf.h"
#include "loop.bpf.h"
#include "output.bpf.h"
#include "vmlinux.h"

// Note on kernel data structures:
//
// - struct super_block:
//     is implemented by each filesystem and is used to store information about
//     that specific filesystem.
//
// - struct vfsmount:
//     contains information about the mount point, such as its location and
//     mount flags. It's contained inside struct mount.
//
// - struct inode:
//     metadata about a file or directory, such as owner, permissions, size,
//     etc. Unix file-systems usually store inodes on a special section on disk,
//     while some other file-systems attach this to the file blob itself.
//
// - struct dentry:
//     a directory entry is a specific component in a path. Among other things,
//     it contains the path component name, a pointer to the parent dentry and a
//     pointer to associated inode. These are not physically persisted on disk
//     and VFS constructs dentry objects on the fly, as needed, when performing
//     directory operations.
//
// - struct file:
//     represent a file opened by a process. It's created in response to the
//     open system call. There can be multiple struct file objects for the same
//     file. The pointed at dentry/inode instead are unique.
//
// - struct path:
//     it's a simple container. A dentry by itself has no pointer to its mount
//     point, making it insufficient for determining a full path. This is why
//     the functions in this file operate on struct path instead.
//     struct path {
//     	struct vfsmount *mnt;
//     	struct dentry *dentry;
//     };
//

#define MAX_PATH_COMPONENTS 20

struct get_path_ctx {
  // Output of get_path_str
  struct buffer *buffer;
  struct buffer_index *index;

  // Current dentry and vfsmount being iterated by get_dentry_name.
  struct path current;

  // Internal list of path components, from dentry to the root
  const unsigned char *component_name[MAX_PATH_COMPONENTS];
  u32 component_len[MAX_PATH_COMPONENTS];
};

static __always_inline long get_dentry_name(u32 i, void *callback_ctx) {
  struct get_path_ctx *c = callback_ctx;
  struct dentry *parent_dentry = BPF_CORE_READ(c->current.dentry, d_parent);

  // Get root dentry of the file-system mount point.
  struct dentry *root_dentry = BPF_CORE_READ(c->current.mnt, mnt_root);

  // If a dentry is the parent of itself, we should have reached to root.
  // The topmost dentry must match root_dentry.
  if (c->current.dentry == parent_dentry && c->current.dentry != root_dentry) {
    LOG_ERROR("We reached root, but not mount root");
    return LOOP_STOP;
  }

  // If we've successfully reached the top of our file-system
  if (c->current.dentry == root_dentry) {
    struct mount *current_mount =
        container_of(c->current.mnt, struct mount, mnt);
    struct mount *parent_mount = BPF_CORE_READ(current_mount, mnt_parent);
    if (current_mount == parent_mount) {
      // Global root - path fully parsed
      return LOOP_STOP;
    } else {
      // We reached root, but not global root - continue with mount point.
      // mnt_mountpoint contains the dentry where this mount point is mounted
      // at.
      c->current.mnt = &parent_mount->mnt;
      c->current.dentry = BPF_CORE_READ(current_mount, mnt_mountpoint);
      return LOOP_CONTINUE;
    }
  }

  // Add this dentry name to path
  struct qstr entry = BPF_CORE_READ(c->current.dentry, d_name);
  if (i < MAX_PATH_COMPONENTS) {
    c->component_len[i] = entry.len;
    c->component_name[i] = entry.name;
  }
  c->current.dentry = parent_dentry;
  return LOOP_CONTINUE;
}

// Build the full path by joining the output components of get_dentry_name.
// The loop starts from the end (t goes from (MAX_PATH_COMPONENTS-1) to 0)
// because the first component will always be the initial dentry.
static __always_inline long append_path_component(u32 i, void *callback_ctx) {
  struct get_path_ctx *c = callback_ctx;
  int t = MAX_PATH_COMPONENTS - i - 1;
  if (t < 0 || t >= MAX_PATH_COMPONENTS)
    return LOOP_STOP;
  char *name = (char *)c->component_name[t];
  int len = c->component_len[t];
  if (len == 0)
    return LOOP_CONTINUE;
  buffer_append_str(c->buffer, c->index, "/", 1);
  buffer_append_str(c->buffer, c->index, name, len);
  return LOOP_CONTINUE;
}

// Copy to buffer/index the path of the file pointed by dentry/path.
static void get_path_str(struct path *path, struct buffer *buffer,
                         struct buffer_index *index) {
  struct get_path_ctx c;
  c.index = index;
  c.buffer = buffer;
  __builtin_memset(c.component_name, 0, sizeof(c.component_name));
  __builtin_memset(c.component_len, 0, sizeof(c.component_len));
  c.current.dentry = path->dentry;
  c.current.mnt = path->mnt;
  buffer_index_init(buffer, index);
  LOOP(MAX_PATH_COMPONENTS, get_dentry_name, &c);
  LOOP(MAX_PATH_COMPONENTS, append_path_component, &c);
  return;
  // TODO: use bpf_d_path when available
}
