/* SPDX-License-Identifier: GPL-2.0-only */
#include "vmlinux.h"

/*
 * `kernfs_node` definition from kernel < 6.15.
 *
 * Unfortunately, it was redefined in a change included in 6.15[0] which is not
 * backwards-compatible and impossible to handle just with BTF. This struct
 * is defined to handle the old definition. The following is a minimal subset
 * of fields required for our use case.
 */

struct kernfs_node___compat {
	struct kernfs_node___compat *parent;
	const char *name;
} __attribute__((preserve_access_index));
