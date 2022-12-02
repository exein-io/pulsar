#pragma once

#include "common.bpf.h"

// Max buffer size in bytes
#define BUFFER_MAX 16384

// A generic buffer attached to an event. This can be sent partially (only the
// used part of the buffer) to userspace.
struct buffer {
  u32 len;
  // buffer is an array of u64 to force an alignment like the Rust code
  u64 buffer[BUFFER_MAX/sizeof(u64)];
};

// A slice inside the buffer. Used inside the tansferred data structures 
// for dynamicly sized arrays.
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
// On success, update index and buffer length.
static void buffer_append_str(struct buffer *buffer,
                                              struct buffer_index *index,
                                              const char *source, int len) {

  int HALF_BUFFER_MASK = (BUFFER_MAX / 2 - 1);
  int pos = (index->start + index->len) & HALF_BUFFER_MASK;
  if (len > HALF_BUFFER_MASK)
  {
    len = HALF_BUFFER_MASK;
  }
  else {
    // include space for terminating 0
    len = (len+1) & HALF_BUFFER_MASK;
  }

  int r = bpf_core_read_str(&((char*) buffer->buffer)[pos], len, source);
  if (r <= 0) {
    LOG_ERROR("redding failure: %d", r);
    return;
  }
  // LOG_DEBUG("New buffer: %s (+%d)", buffer->buffer, r);

  // Update counters, ignoring the final 0.
  index->len += r - 1;
  buffer->len += r - 1;
}
