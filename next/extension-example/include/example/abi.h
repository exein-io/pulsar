/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
// Records of the example extension's producer (probes/syscalls.bpf.c). The
// rules of pulsar/abi.h apply.
#pragma once

#include "pulsar/abi.h"

enum example_kind {
  EXAMPLE_SYSCALL_ACTIVITY = 1,
};

// Syscalls numbered below this are counted one by one, the others only in
// `total`. A larger histogram would make the record too large to reserve.
#define EXAMPLE_SYSCALLS_MAX 64

// Fixed size. Written when the process exits.
struct example_syscall_activity {
  __u64 total;
  __u64 histogram[EXAMPLE_SYSCALLS_MAX];
};

struct example_syscall_activity_record {
  struct pulsar_record_header header;
  struct example_syscall_activity body;
};
