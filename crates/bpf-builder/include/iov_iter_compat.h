/* SPDX-License-Identifier: GPL-2.0-only */
#include "vmlinux.h"

/*
 * `iov_iter` definition from kernel <= 6.4.
 *
 * Unfortunately, it was redefined in a change included in 6.4[0] which is not
 * backwards-compatible and impossible to handle just with BTF. This struct
 * is defined to handle the old definition.
 */
struct iov_iter_compat {
	u8 iter_type;
	bool data_source;
	size_t iov_offset;
	size_t count;
	union {
		const struct iovec *iov;
		const struct kvec *kvec;
		const struct bio_vec *bvec;
		struct xarray *xarray;
		struct pipe_inode_info *pipe;
	};
	union {
		long unsigned int nr_segs;
		struct {
			unsigned int head;
			unsigned int start_head;
		};
		loff_t xarray_start;
	};
};
