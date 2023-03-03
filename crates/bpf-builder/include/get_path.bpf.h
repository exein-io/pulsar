#pragma once
#include "loop.bpf.h"
#include "output.bpf.h"

#define MAX_PATH_COMPONENTS 20

struct get_path_ctx {
  // Output of get_path_str
  struct buffer *buffer;
  struct buffer_index *index;

  // Current dentry being iterated
  struct dentry *dentry;
  struct vfsmount *vfsmnt;
  struct mount *mnt_p;
  struct mount *mnt_parent_p;

  // Internal list of path components, from dentry to the root
  const unsigned char *component_name[MAX_PATH_COMPONENTS];
  u32 component_len[MAX_PATH_COMPONENTS];
};

static __always_inline long get_dentry_name(u32 i, void *callback_ctx) {
  struct get_path_ctx *c = callback_ctx;
  if (!c)
    return 1;
  struct dentry *mnt_root = (struct dentry *)BPF_CORE_READ(c->vfsmnt, mnt_root);
  struct dentry *d_parent = BPF_CORE_READ(c->dentry, d_parent);
  // If a dentry is the parent of itself, or if it matches the root
  if (c->dentry == mnt_root || c->dentry == d_parent) {
    if (c->dentry != mnt_root) {
      // We reached root, but not mount root - escaped?
      return 1;
    }
    if (c->mnt_p != c->mnt_parent_p) {
      // We reached root, but not global root - continue with mount point
      c->dentry = BPF_CORE_READ(c->mnt_p, mnt_mountpoint);
      c->mnt_p = BPF_CORE_READ(c->mnt_p, mnt_parent);
      c->mnt_parent_p = BPF_CORE_READ(c->mnt_p, mnt_parent);
      c->vfsmnt = &c->mnt_p->mnt;
      return 0;
    }
    // Global root - path fully parsed
    return 1;
  }
  // Add this dentry name to path
  struct qstr entry = BPF_CORE_READ(c->dentry, d_name);
  if (i < MAX_PATH_COMPONENTS) {
    c->component_len[i] = entry.len;
    c->component_name[i] = entry.name;
  }
  c->dentry = d_parent;
  return 0;
}

// Build the full path by joining the output components of get_dentry_name.
// The loop starts from the end (t goes from (MAX_PATH_COMPONENTS-1) to 0)
// because the first component will always be the initial dentry.
static __always_inline long append_path_component(u32 i, void *callback_ctx) {
  struct get_path_ctx *c = callback_ctx;
  int t = MAX_PATH_COMPONENTS - i - 1;
  if (t < 0 || t >= MAX_PATH_COMPONENTS)
    return 1;
  char *name = (char *)c->component_name[t];
  int len = c->component_len[t];
  if (len == 0)
    return 0;
  buffer_append_str(c->buffer, c->index, "/", 1);
  buffer_append_str(c->buffer, c->index, name, len);
  return 0;
}

// Copy to buffer/index the path of the file pointed by dentry/path.
static void get_path_str(struct dentry *dentry, struct path *path,
                         struct buffer *buffer, struct buffer_index *index) {
  struct get_path_ctx c;
  c.index = index;
  c.buffer = buffer;
  __builtin_memset(c.component_name, 0, sizeof(c.component_name));
  __builtin_memset(c.component_len, 0, sizeof(c.component_len));
  c.dentry = dentry;
  c.vfsmnt = BPF_CORE_READ(path, mnt);
  c.mnt_p = container_of(c.vfsmnt, struct mount, mnt);
  c.mnt_parent_p = BPF_CORE_READ(c.mnt_p, mnt_parent);
  buffer_index_init(buffer, index);
  LOOP(MAX_PATH_COMPONENTS, get_dentry_name, &c);
  LOOP(MAX_PATH_COMPONENTS, append_path_component, &c);
  return;
}
