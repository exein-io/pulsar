/* SPDX-License-Identifier: GPL-2.0-only */
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

#define MAX_PATH_COMPONENTS 100
#define MAX_PATH_UNROLL 20

// Array of path components which is kept inside `struct ctx_get_path`.
// bpf_loop requires `ctx_get_path` to be a stack variable, but that prevents
// us to store MAX_PATH_COMPONENTS items inside, as that's more than the allowed
// stack space for eBPF programs. For this reason we allocate them on a
// temporary PERCPU_ARRAY map.
struct components {
  u32 total_components;
  const unsigned char *component_name[MAX_PATH_COMPONENTS];
  u32 component_len[MAX_PATH_COMPONENTS];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct components);
  __uint(max_entries, 1);
} components_map SEC(".maps");

struct ctx_get_path {
  // Output of get_path_str
  struct buffer *buffer;
  struct buffer_index *index;

  // Current dentry and vfsmount being iterated by loop_get_dentry_name.
  struct path current;

  // Internal list of path components, from dentry to the root
  struct components *components;
};

// Used to iterate over all the dentry ancestors of a file and append
// their name to struct components.
static __always_inline long loop_get_dentry_name(u32 i, void *callback_ctx) {
  struct ctx_get_path *c = callback_ctx;
  // NOTE: we need to store fields in temporary variables because a call like
  // the the following results in a relocation error in kernel 5.5 x86:
  // BPF_CORE_READ(c->current.dentry, d_parent);
  // > applying relocation `FieldByteOffset` missing target BTF info for type
  //   `909` at instruction #472
  // This happens only in `sched_process_exec`, which uses raw tracepoints,
  // while it doesn't happen in file-system-monitor, which uses lsm/kprobe
  // programs.
  struct dentry *current_dentry = c->current.dentry;
  struct vfsmount *current_mnt = c->current.mnt;
  struct dentry *parent_dentry = BPF_CORE_READ(current_dentry, d_parent);

  // Get root dentry of the file-system mount point.
  struct dentry *root_dentry = BPF_CORE_READ(current_mnt, mnt_root);

  // If a dentry is the parent of itself, we should have reached to root.
  // The topmost dentry must match root_dentry.
  if (current_dentry == parent_dentry && current_dentry != root_dentry) {
    LOG_ERROR("We reached root, but not mount root");
    return LOOP_STOP;
  }

  // If we've successfully reached the top of our file-system
  if (current_dentry == root_dentry) {
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
  struct qstr entry = BPF_CORE_READ(current_dentry, d_name);
  u32 next = c->components->total_components;
  if (next < MAX_PATH_COMPONENTS) {
    c->components->component_len[next] = entry.len;
    c->components->component_name[next] = entry.name;
    c->components->total_components++;
  }
  c->current.dentry = parent_dentry;
  return LOOP_CONTINUE;
}

// Build the full path by joining the output components of loop_get_dentry_name.
// The loop starts from the end (t goes from (MAX_PATH_COMPONENTS-1) to 0)
// because the first component will always be the initial dentry.
static __always_inline long loop_append_path_component(u32 i,
                                                       void *callback_ctx) {
  struct ctx_get_path *c = callback_ctx;
  int t = c->components->total_components - i - 1;
  if (t < 0 || t >= MAX_PATH_COMPONENTS)
    return LOOP_STOP;
  char *name = (char *)c->components->component_name[t];
  int len = c->components->component_len[t];
  buffer_append_str(c->buffer, c->index, "/", 1, 0);
  buffer_append_str(c->buffer, c->index, name, len, 0);
  return LOOP_CONTINUE;
}

// Copy to buffer/index the path of the file pointed by dentry/path.
static void get_path_str(struct path *path, struct buffer *buffer,
                         struct buffer_index *index) {

  u32 key = 0;
  struct ctx_get_path c;
  struct components *components = bpf_map_lookup_elem(&components_map, &key);
  if (!components) {
    LOG_ERROR("can't get context memory");
    return;
  }
  c.components = components;
  components->total_components = 0;
  c.index = index;
  c.buffer = buffer;
  c.current.dentry = path->dentry;
  c.current.mnt = path->mnt;
  buffer_index_init(buffer, index);
  LOOP(MAX_PATH_COMPONENTS, MAX_PATH_UNROLL, loop_get_dentry_name, &c);
  LOOP(MAX_PATH_COMPONENTS, MAX_PATH_UNROLL, loop_append_path_component, &c);
}
