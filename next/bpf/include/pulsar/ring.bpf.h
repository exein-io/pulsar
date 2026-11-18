/* SPDX-License-Identifier: GPL-2.0-only */
// Writing records into the shared ring buffer.
//
// Every Pulsar object, and every extension object, includes this header. All
// of them write into the same `pulsar_events` ring and count lost records in
// the same `pulsar_lost` array: userspace loads every object with the same pin
// directory and ring size, so the second object loaded reuses the maps pinned
// by the first. Records from all probes on all CPUs then reach userspace in
// one order, the order in which they were reserved.
//
// Records (see pulsar/abi.h) are emitted in one of two ways.
//
// Fixed-size kinds are written in place in the ring:
//
//   struct pulsar_process_exit_record *rec = PULSAR_RESERVE(
//       struct pulsar_process_exit_record, PULSAR_PROCESS_EXIT, task);
//   if (!rec)
//     return 0;
//   rec->body.exit_code = ...;
//   pulsar_submit(rec); // or pulsar_discard(rec)
//
// The verifier rejects a program that can return while holding a reservation.
//
// Variable-size kinds are built in a per-CPU scratch slot and copied into the
// ring, because a reservation's size must be a compile-time constant and the
// ring keeps all of it:
//
//   PULSAR_SCRATCH_TYPE(pulsar_process_exec); // once, at file scope
//
//   struct pulsar_process_exec_scratch *rec = PULSAR_SCRATCH(
//       struct pulsar_process_exec_scratch, PULSAR_PROCESS_EXEC, task);
//   if (!rec)
//     return 0;
//   buffer_index_init(&rec->buffer, &rec->body.filename);
//   ...
//   PULSAR_OUTPUT(rec); // or pulsar_scratch_release()
//
// Once PULSAR_SCRATCH succeeded, exactly one of PULSAR_OUTPUT and
// pulsar_scratch_release must follow; nothing checks it.
//
// Every record that could not be written is counted by pulsar_count_lost.
// That is the one place where load shedding would go.
#pragma once

#include "vmlinux.h"

#include "abi.h"
#include "buffer.bpf.h"
#include "common.bpf.h"

// Set by userspace when it loads the object, below PULSAR_PRODUCER_MAX.
const volatile __u32 PULSAR_PRODUCER_ID = 0;

// ABI stamp. The name of this global carries the version of pulsar/abi.h the
// object was built against (PULSAR_ABI_V1, ...). Userspace sets the global of
// its own version and refuses an object where it doesn't exist.
#define PULSAR_ABI_STAMP_NAME(version) PULSAR_ABI_V##version
#define PULSAR_ABI_STAMP(version) PULSAR_ABI_STAMP_NAME(version)
const volatile __u32 PULSAR_ABI_STAMP(PULSAR_ABI_VERSION) = 0;

// Userspace sets the real size of the ring when it loads the object.
#define PULSAR_RING_DEFAULT_SIZE (8 * 1024 * 1024)

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, PULSAR_RING_DEFAULT_SIZE);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} pulsar_events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, PULSAR_LOST_TOTAL + 1 + PULSAR_PRODUCER_MAX);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} pulsar_lost SEC(".maps");

// Counts a record that could not be written, in total and for this producer.
// Relaxed: clang 23 compiles the __sync builtins to fetching atomics, which
// need kernel 5.12, even when the result is unused.
static __always_inline void pulsar_count_lost(void) {
  __u32 key = PULSAR_LOST_TOTAL;
  __u64 *total = bpf_map_lookup_elem(&pulsar_lost, &key);
  if (total)
    __atomic_fetch_add(total, 1, __ATOMIC_RELAXED);
  key = PULSAR_LOST_TOTAL + 1 + PULSAR_PRODUCER_ID;
  __u64 *own = bpf_map_lookup_elem(&pulsar_lost, &key);
  if (own)
    __atomic_fetch_add(own, 1, __ATOMIC_RELAXED);
}

static __always_inline __u32 pulsar_lost_snapshot(void) {
  __u32 key = PULSAR_LOST_TOTAL;
  __u64 *total = bpf_map_lookup_elem(&pulsar_lost, &key);
  return total ? (__u32)*total : 0;
}

// Fills @subject from @task. Not inlined: it runs at every emission site,
// including the unrolled loop of sched_switch.
static __noinline void pulsar_subject_fill(struct pulsar_subject *subject,
                                           struct task_struct *task) {
  struct task_struct *leader = BPF_CORE_READ(task, group_leader);
  subject->tgid = BPF_CORE_READ(task, tgid);
  subject->ppid = BPF_CORE_READ(task, real_parent, tgid);
  subject->start_time = BPF_CORE_READ(leader, start_boottime);
  subject->uid = BPF_CORE_READ(task, cred, uid.val);
  subject->gid = BPF_CORE_READ(task, cred, gid.val);
  subject->exec_id = BPF_CORE_READ(leader, self_exec_id);
  subject->cgroup_id = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, id);
}

// Fills everything in @header except `size` and `lost`, which are written
// right before the record enters the ring. @header must be zeroed.
static __always_inline void
pulsar_header_fill(struct pulsar_record_header *header, __u16 kind,
                   struct task_struct *task) {
  header->producer = (__u16)PULSAR_PRODUCER_ID;
  header->kind = kind;
  header->timestamp = bpf_ktime_get_boot_ns();
  pulsar_subject_fill(&header->subject, task);
}

// --------------------------- Fixed-size records ---------------------------

#define PULSAR_RESERVE(type, kind, task)                                       \
  ((type *)pulsar_reserve(sizeof(type), kind, task))

// Reserves @size bytes in the ring and fills the record header for @task.
// @size must be a compile-time constant.
static __always_inline void *pulsar_reserve(__u32 size, __u16 kind,
                                            struct task_struct *task) {
  struct pulsar_record_header *header =
      bpf_ringbuf_reserve(&pulsar_events, size, 0);
  if (!header) {
    pulsar_count_lost();
    return NULL;
  }
  // The ring's memory isn't zeroed, and fields left unwritten must read as
  // zero (PULSAR_FIELD_MISSING).
  __builtin_memset(header, 0, size);
  header->size = size;
  header->lost = pulsar_lost_snapshot();
  pulsar_header_fill(header, kind, task);
  return header;
}

static __always_inline void pulsar_submit(void *record) {
  bpf_ringbuf_submit(record, 0);
}

static __always_inline void pulsar_discard(void *record) {
  bpf_ringbuf_discard(record, 0);
}

// -------------------------- Variable-size records -------------------------

// eBPF programs could interrupt each other, see "Are BPF programs preemptible?"
// thread on the kernel BPF mailing list:
// https://lore.kernel.org/bpf/878rhty100.fsf@cloudflare.com/T/#t
#define MAX_PREEMPTION_NESTING_LEVEL 3

// Largest header + body of a variable-size kind.
#define PULSAR_SCRATCH_RECORD_MAX 256

// Map values are 8-byte aligned. Saying so lets clang zero a slot with 8-byte
// stores: with byte stores, a record needs more than it inlines, and clang 23
// emits a call to memset, which can't be loaded.
struct pulsar_scratch_slot {
  __u8 bytes[PULSAR_SCRATCH_RECORD_MAX + sizeof(struct pulsar_buffer)];
} __attribute__((aligned(8)));

// The BPF stack limit of 512 bytes is exceeded by a record with its buffer, so
// we use a per-cpu array as a workaround.
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct pulsar_scratch_slot);
  __uint(max_entries, MAX_PREEMPTION_NESTING_LEVEL);
} pulsar_scratch SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, u64);
  __uint(max_entries, 1);
} pulsar_scratch_nesting SEC(".maps");

// Declares `struct <name>_scratch`: the record of a variable-size kind as it
// is built in a scratch slot, with room for its tail bytes. <name> is the body
// type, and `struct <name>_record` must be its record in pulsar/abi/*.h.
#define PULSAR_SCRATCH_TYPE(name)                                              \
  struct name##_scratch {                                                      \
    struct pulsar_record_header header;                                        \
    struct name body;                                                          \
    struct pulsar_buffer buffer;                                               \
  };                                                                           \
  _Static_assert(__builtin_offsetof(struct name##_scratch, buffer) ==          \
                     __builtin_offsetof(struct name##_record, tail),           \
                 "the scratch record must match the record of " #name);        \
  _Static_assert(sizeof(struct name##_scratch) <=                              \
                     sizeof(struct pulsar_scratch_slot),                       \
                 "the record of " #name " doesn't fit in a scratch slot")

// Get a value and increment it by one
static __always_inline u64 sync_increment(u64 *value) {
#ifdef FEATURE_ATOMICS
  return __sync_fetch_and_add(value, 1);
#else
  // If we miss atomic operations, it still shouldn't cause problems:
  // - the nesting levels are kept on a PERCPU array
  // - even if an eBPF program interrupts this, the nesting level
  //   will be left in a consistent state as all eBPF programs will
  //   reset the counter to its previous value before exiting.
  u64 old_value = *value;
  *value += 1;
  return old_value;
#endif
}

// Decrement value by one
static __always_inline u64 sync_decrement(u64 *value) {
#ifdef FEATURE_ATOMICS
  return __sync_fetch_and_sub(value, 1);
#else
  u64 old_value = *value;
  *value -= 1;
  return old_value;
#endif
}

static __always_inline void pulsar_scratch_release(void) {
  u32 zero = 0;
  u64 *nesting_level = bpf_map_lookup_elem(&pulsar_scratch_nesting, &zero);
  if (!nesting_level) {
    LOG_ERROR("can't get nesting counter");
    return;
  }
  u64 old_value = sync_decrement(nesting_level);
  if (old_value <= 0) {
    LOG_ERROR("nesting_level = %d before decrement", old_value);
    sync_increment(nesting_level);
  }
}

static __always_inline int pulsar_scratch_acquire(void) {
  u32 zero = 0;
  u64 *nesting_level = bpf_map_lookup_elem(&pulsar_scratch_nesting, &zero);
  if (!nesting_level) {
    LOG_ERROR("can't get nesting counter");
    return -1;
  }
  u64 old_value = sync_increment(nesting_level);
  if (old_value > 0) {
    // This is not an error, but being so uncommon, it may sill make sense to
    // log it
    LOG_DEBUG("Preemption actually happend: nesting_level = %d", old_value + 1);
  }
  if (old_value >= MAX_PREEMPTION_NESTING_LEVEL) {
    LOG_ERROR("nesting_level = %d", old_value);
    sync_decrement(nesting_level);
    return -1;
  }
  return old_value;
}

#define PULSAR_SCRATCH(type, kind, task)                                       \
  ((type *)pulsar_scratch_init(__builtin_offsetof(type, buffer.data), kind,    \
                               task))

// Takes a scratch slot and fills the record header for @task. The first
// @zeroed bytes (header, body and buffer length) are zeroed. The buffer's
// bytes are not: they still hold whatever the previous record left there.
static __always_inline void *pulsar_scratch_init(__u32 zeroed, __u16 kind,
                                                 struct task_struct *task) {
  int nesting_level = pulsar_scratch_acquire();
  if (nesting_level < 0) {
    pulsar_count_lost();
    return NULL;
  }
  u32 key = nesting_level;
  struct pulsar_scratch_slot *slot = bpf_map_lookup_elem(&pulsar_scratch, &key);
  if (!slot) {
    LOG_ERROR("can't get event memory for nesting level %d", nesting_level);
    pulsar_scratch_release();
    pulsar_count_lost();
    return NULL;
  }
  __builtin_memset(slot, 0, zeroed);
  pulsar_header_fill((struct pulsar_record_header *)slot, kind, task);
  return slot;
}

#define PULSAR_OUTPUT(record)                                                  \
  pulsar_output((record), __builtin_offsetof(typeof(*(record)), buffer.data),  \
                (record)->buffer.len)

// Copies the record built in a scratch slot into the ring: @data_offset bytes
// of header, body and buffer length, followed by @data_len buffer bytes.
// Releases the slot.
static __always_inline void pulsar_output(void *record, __u32 data_offset,
                                          __u32 data_len) {
  if (data_len >= BUFFER_MAX) {
    LOG_ERROR("invalid buffer.len = %d, skipping event", data_len);
    pulsar_count_lost();
  } else {
    struct pulsar_record_header *header = record;
    __u32 size = data_offset + data_len;
    header->size = size;
    header->lost = pulsar_lost_snapshot();
    long ret = bpf_ringbuf_output(&pulsar_events, record, size, 0);
    if (ret) {
      LOG_DEBUG("error %d emitting event of len %d", ret, size);
      pulsar_count_lost();
    }
  }
  pulsar_scratch_release();
}
