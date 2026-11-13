/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
// Records written by Pulsar probes into the shared ring buffer.
//
// This header and pulsar/abi/*.h are the single definition of the records:
// probes include them and the Rust types are generated from them with bindgen.
// They must stay plain C: fixed-width integer types only, no vmlinux.h types,
// and no bool or enum fields (enums only name constants).
//
// A record is laid out as
//
//   struct pulsar_record_header  producer, kind, size, when, which process
//   body of the kind             fixed size, in pulsar/abi/<producer>.h
//   struct pulsar_tail + bytes   variable-size kinds only
//
// and `header.size` counts all of it. Variable fields live in the tail bytes
// and are referenced from the body by a `struct pulsar_buffer_index`.
//
// A record is identified by (producer, kind). Userspace assigns the producer id
// when it loads an object; each producer defines its own kinds.
//
// Anything a probe failed to read is marked as missing (a `pulsar_field_status`
// or a `missing` bit in the body) instead of being dropped with the record.
#pragma once

#if defined(__bpf__)
#include "vmlinux.h"
#else
#include <linux/types.h>
#endif

#define PULSAR_ABI_VERSION 1

// Producer ids are below this; `pulsar_lost` has one slot per producer.
#define PULSAR_PRODUCER_MAX 64

// `pulsar_lost` slot counting every lost record. The slot of a producer is
// PULSAR_LOST_TOTAL + 1 + producer.
#define PULSAR_LOST_TOTAL 0

// header.flags: the subject is unknown and zeroed.
#define PULSAR_F_UNATTRIBUTED (1u << 0)

// The process a record is about.
struct pulsar_subject {
  __u32 tgid;
  __u32 ppid;
  // group_leader->start_boottime: with tgid, identifies the process across
  // pid reuse.
  __u64 start_time;
  __u32 uid;
  __u32 gid;
  // group_leader->self_exec_id: incremented by every exec.
  __u64 exec_id;
  // cgroup v2 id.
  __u64 cgroup_id;
};

struct pulsar_record_header {
  __u16 producer;
  __u16 kind;
  __u32 size;
  // PULSAR_F_*
  __u32 flags;
  // Low 32 bits of the PULSAR_LOST_TOTAL counter when the record was written.
  // A jump between two records means records were lost between them.
  __u32 lost;
  // bpf_ktime_get_boot_ns(): the clock of subject.start_time.
  __u64 timestamp;
  struct pulsar_subject subject;
};

// Zero is "missing", so a field that was never written can't look present.
enum pulsar_field_status {
  PULSAR_FIELD_MISSING = 0,
  PULSAR_FIELD_PRESENT = 1,
  // Only part of the value could be read.
  PULSAR_FIELD_TRUNCATED = 2,
};

// A variable-size field: `len` bytes at offset `start` of the tail bytes.
struct pulsar_buffer_index {
  __u16 start;
  __u16 len;
  // enum pulsar_field_status
  __u16 status;
  __u16 reserved;
};

// Last member of a variable-size record. `len` bytes follow it.
struct pulsar_tail {
  __u32 len;
};
