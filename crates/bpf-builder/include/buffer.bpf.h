/* SPDX-License-Identifier: GPL-2.0-only */

// Allow the eBPF side to send a buffer of dynamically sized arguments.
//
// The eBPF program sends event structures over a PerfEventArray, which the
// userspace reads in `bpf-common/src/program.rs`. They need to be a blob of raw
// memory which must have the same binary representation in C and Rust, hence
// the Rust struct must be `repr(C)`.
//
// Originally, if the eBPF program wanted to send a string (eg. the path of a
// file) we would have added to the event struct an array field with a fixed
// length. This resulted in:
// - Frequent large copies of mostly empty arrays
// - Inability to support infrequent exceptionally large arguments
//
// The solution is to always append a generic buffer after the event definition:
// struct event_t {
//   u64 timestamp;
//   pid_t pid;
//   struct buffer_index path1;
//   struct buffer_index path2;
//   struct buffer buffer
// }
//
// This will have a large maximum size of BUFFER_MAX, but only the used part
// will be copied over on event output. A list of buffer indexes will be used
// to specify the start and length of a given dynamic field.

#pragma once

#include "common.bpf.h"

// Allocated size of the buffer
#define BUFFER_MAX 16384
// FIXME: To satisfy the eBPF validator, half of the buffer is unused. The
// chunks we write have a max length of HALF_BUFFER_MASK and can start only
// up to HALF_BUFFER_MASK.
#define HALF_BUFFER_MASK (BUFFER_MAX / 2 - 1)

// A generic buffer attached to an event. This can be sent partially (only the
// used part of the buffer) to userspace.
struct buffer {
  // number of filled bytes
  u32 len;
  // buffer is an array of u64 to force an alignment like the Rust code
  u64 buffer[BUFFER_MAX / sizeof(u64)];
};

// A slice inside the buffer. Used inside the transferred data structures
// for dynamically sized arrays.
struct buffer_index {
  u16 start;
  u16 len;
};

/// Create an empty buffer index pointing to first free buffer section
static void buffer_index_init(struct buffer *buffer,
                              struct buffer_index *index) {
  index->start = buffer->len;
  index->len = 0;
}

// Copy up to len bytes from source to the buffer pointed by index.
// On success, update index and buffer length. Source is treated as a string:
// the copy will be interrupted when encountering a NULL byte.
static void buffer_append_str(struct buffer *buffer, struct buffer_index *index,
                              const char *source, int len) {
  int pos = (index->start + index->len);
  if (pos >= HALF_BUFFER_MASK) {
    LOG_ERROR("trying to write over half: %d+%d", index->start, index->len);
    return;
  }
  if (len > HALF_BUFFER_MASK) {
    len = HALF_BUFFER_MASK;
  } else {
    // include space for terminating 0
    len = (len + 1) & HALF_BUFFER_MASK;
  }

  int r = bpf_core_read_str(&((char *)buffer->buffer)[pos], len, source);
  if (r <= 0) {
    LOG_ERROR("reading failure: %d", r);
    return;
  }
  // LOG_DEBUG("New buffer: %s (+%d)", buffer->buffer, r);

  // Update counters, ignoring the final 0.
  index->len += r - 1;
  buffer->len += r - 1;
}

// Copy up to len bytes from source to the buffer pointed by index.
// On success, update index and buffer length.
// Source must point to user memory.
static void buffer_append_user_memory(struct buffer *buffer,
                                      struct buffer_index *index, void *source,
                                      int len) {
  int pos = (index->start + index->len);
  if (pos >= HALF_BUFFER_MASK) {
    LOG_ERROR("trying to write over half: %d+%d", index->start, index->len);
    return;
  }
  int r = bpf_core_read_user(&((char *)buffer->buffer)[pos],
                             len & HALF_BUFFER_MASK, source);
  if (r < 0) {
    LOG_ERROR("reading failure: %d", r);
    return;
  }
  // LOG_DEBUG("New buffer: %s (+%d)", buffer->buffer, r);

  index->len += len;
  buffer->len += len;
}

static __always_inline void buffer_append_skb_bytes(struct buffer *buffer,
                                                    struct buffer_index *index,
                                                    struct __sk_buff *skb,
                                                    __u32 offset) {
  int pos = (index->start + index->len);
  if (pos >= HALF_BUFFER_MASK) {
    LOG_ERROR(
      "Attempting to write beyond buffer capacity. Calculated position: %zu, capacity: %d.",
      pos, HALF_BUFFER_MASK
    );
    return;
  }

  s32 len = skb->len - offset;
  if (len >= HALF_BUFFER_MASK) {
    LOG_ERROR("Payload size (%d) exceeds buffer capacity (%d).",
              len, HALF_BUFFER_MASK);
    return;
  }

  if (len <= 0) {
    LOG_ERROR("Invalid offset (%zu) exceeding the packet length (%zu).",
              offset, skb->len);
    return;
  }

  int r = bpf_skb_load_bytes(skb, offset, &((char *)buffer->buffer)[pos],
                             len);
    
  if (r < 0) {
    LOG_ERROR("Could not read the network packet payload: %d", r);
    return;
  }

  index->len += len;
  buffer->len += len;
}
