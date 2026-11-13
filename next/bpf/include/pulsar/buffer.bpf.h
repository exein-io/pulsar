/* SPDX-License-Identifier: GPL-2.0-only */

// Allow the eBPF side to send a buffer of dynamically sized arguments.
//
// Originally, if the eBPF program wanted to send a string (eg. the path of a
// file) we would have added to the event struct an array field with a fixed
// length. This resulted in:
// - Frequent large copies of mostly empty arrays
// - Inability to support infrequent exceptionally large arguments
//
// The solution is to end variable-size records with a generic buffer, which is
// the record's tail (see pulsar/abi.h):
// struct pulsar_X_scratch {
//   struct pulsar_record_header header;
//   struct pulsar_X body;           // holds struct pulsar_buffer_index fields
//   struct pulsar_buffer buffer;
// }
//
// This will have a large maximum size of BUFFER_MAX, but only the used part
// will be copied over on event output. A list of buffer indexes will be used
// to specify the start and length of a given dynamic field, and whether it
// could be read.

#pragma once

#include "abi.h"
#include "common.bpf.h"

// Allocated size of the buffer
#define BUFFER_MAX 16384
// FIXME: To satisfy the eBPF validator, half of the buffer is unused. The
// chunks we write have a max length of HALF_BUFFER_MASK and can start only
// up to HALF_BUFFER_MASK.
#define HALF_BUFFER_MASK (BUFFER_MAX / 2 - 1)

// A generic buffer attached to an event. This can be sent partially (only the
// used part of the buffer) to userspace. On the wire, `len` is the record's
// `struct pulsar_tail` and `data` the bytes that follow it.
struct pulsar_buffer {
  // number of filled bytes
  u32 len;
  u8 data[BUFFER_MAX];
};

_Static_assert(__builtin_offsetof(struct pulsar_buffer, data) ==
                   sizeof(struct pulsar_tail),
               "the tail bytes must follow struct pulsar_tail");

/// Create an empty buffer index pointing to first free buffer section
static void buffer_index_init(struct pulsar_buffer *buffer,
                              struct pulsar_buffer_index *index) {
  index->start = buffer->len;
  index->len = 0;
  index->status = PULSAR_FIELD_MISSING;
  index->reserved = 0;
}

// Records the outcome of one append to the field at @index, before its length
// is updated. A failed read leaves the field missing for good, even if later
// appends succeed, and a truncated field stays truncated.
static __always_inline void buffer_index_mark(struct pulsar_buffer_index *index,
                                              u16 outcome) {
  if (index->status == PULSAR_FIELD_MISSING && index->len > 0)
    return;
  if (index->status == PULSAR_FIELD_TRUNCATED &&
      outcome == PULSAR_FIELD_PRESENT)
    return;
  if (outcome == PULSAR_FIELD_TRUNCATED && index->len == 0)
    outcome = PULSAR_FIELD_MISSING;
  index->status = outcome;
}

// Copies up to @len bytes from @source, starting from the given @offset, to
// the @buffer pointed by @index.
//
// On success, update index and buffer length. Source is treated as a string:
// the copy will be interrupted when encountering a NULL byte.
static __always_inline void buffer_append_str(struct pulsar_buffer *buffer,
                                              struct pulsar_buffer_index *index,
                                              const char *source, u32 len,
                                              u32 offset) {
  int pos = (index->start + index->len);
  if (pos >= HALF_BUFFER_MASK) {
    LOG_ERROR("trying to write over half: %d+%d", index->start, index->len);
    buffer_index_mark(index, PULSAR_FIELD_TRUNCATED);
    return;
  }

  bool capped = false;
  s32 partial_len = len - offset;
  if (partial_len > HALF_BUFFER_MASK) {
    partial_len = HALF_BUFFER_MASK;
    capped = true;
  } else {
    partial_len = (partial_len + 1) & HALF_BUFFER_MASK;
  }
  if (partial_len <= 0) {
    LOG_ERROR("offset out of bounds: %u+%u", offset, len);
    buffer_index_mark(index, PULSAR_FIELD_MISSING);
    return;
  }

  int r = bpf_core_read_str(&buffer->data[pos], partial_len, source + offset);
  if (r <= 0) {
    LOG_ERROR("reading failure: %d", r);
    buffer_index_mark(index, PULSAR_FIELD_MISSING);
    return;
  }
  // LOG_DEBUG("New buffer: %s (+%d)", buffer->data, r);

  // A string that filled the capped read may have been cut.
  buffer_index_mark(index, capped && r == partial_len ? PULSAR_FIELD_TRUNCATED
                                                      : PULSAR_FIELD_PRESENT);

  // Update counters, ignoring the final 0.
  index->len += r - 1;
  buffer->len += r - 1;
}

// Copy up to len bytes from source to the buffer pointed by index.
// On success, update index and buffer length. What doesn't fit is cut, and
// the field is marked truncated.
// Source must point to user memory.
static __always_inline int
buffer_append_user_memory(struct pulsar_buffer *buffer,
                          struct pulsar_buffer_index *index, void *source,
                          u32 len) {
  // The verifier needs `pos` and `len` bounded separately: a bound on their
  // sum tells it nothing about either, and the sum can wrap.
  u32 pos = index->start + index->len;
  if (pos >= HALF_BUFFER_MASK) {
    LOG_ERROR("trying to write over half: %d+%d", index->start, index->len);
    buffer_index_mark(index, PULSAR_FIELD_TRUNCATED);
    return -1;
  }
  u16 outcome = PULSAR_FIELD_PRESENT;
  if (len >= HALF_BUFFER_MASK) {
    LOG_DEBUG("write of %d bytes exceeds buffer capacity (%d)", len,
              HALF_BUFFER_MASK);
    len = HALF_BUFFER_MASK - 1;
    outcome = PULSAR_FIELD_TRUNCATED;
  }
  // After the clamp clang may pass the helper a register the verifier has no
  // bound for. The barrier keeps this check on the register that is passed.
  barrier_var(len);
  if (len >= HALF_BUFFER_MASK)
    return -1;

  int r = bpf_core_read_user(&buffer->data[pos], len, source);
  if (r < 0) {
    LOG_ERROR("reading failure: %d", r);
    buffer_index_mark(index, PULSAR_FIELD_MISSING);
    return -1;
  }

  buffer_index_mark(index, outcome);
  index->len += len;
  buffer->len += len;

  return 0;
}

static __always_inline int
buffer_append_skb_bytes(struct pulsar_buffer *buffer,
                        struct pulsar_buffer_index *index,
                        struct __sk_buff *skb, u32 offset) {
  int pos = (index->start + index->len);
  if (pos >= HALF_BUFFER_MASK) {
    LOG_ERROR("Attempting to write beyond buffer capacity. Calculated "
              "position: %zu, capacity: %d.",
              pos, HALF_BUFFER_MASK);
    buffer_index_mark(index, PULSAR_FIELD_TRUNCATED);
    return -1;
  }

  u16 outcome = PULSAR_FIELD_PRESENT;
  s32 len = skb->len - offset;
  if (len >= HALF_BUFFER_MASK) {
    LOG_DEBUG("Payload size (%d) exceeds buffer capacity (%d).", len,
              HALF_BUFFER_MASK);
    len = HALF_BUFFER_MASK - 1;
    outcome = PULSAR_FIELD_TRUNCATED;
  }
  // See buffer_append_user_memory.
  barrier_var(len);
  if (len >= HALF_BUFFER_MASK)
    return -1;

  // * The `< 0` case means `offset` (the packet headers already consumed by
  //   the caller) is larger than `skb->len`. Callers are expected to validate
  //   header lengths coming from the wire (e.g. the TCP data offset) before
  //   getting here, so this is a defensive check. Using `s32` (instead of
  //   `u32` and checking just for `0`) also appeases the eBPF verifier.
  // * The `= 0` case usually applies to SYN, SYN-ACK, ACK or any other packets
  //   which don't contain any payload after L4 headers.
  //   Therefore, we don't return any error here.
  if (len <= 0) {
    buffer_index_mark(index, PULSAR_FIELD_PRESENT);
    return 0;
  }

  int r = bpf_skb_load_bytes(skb, offset, &buffer->data[pos], len);

  if (r < 0) {
    LOG_ERROR("Could not read the network packet payload: %d", r);
    buffer_index_mark(index, PULSAR_FIELD_MISSING);
    return -1;
  }

  buffer_index_mark(index, outcome);
  index->len += len;
  buffer->len += len;

  return 0;
}
