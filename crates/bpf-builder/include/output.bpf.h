/// Manage output to userspace using a perf event array map
#pragma once

#include "buffer.bpf.h"

#define OUTPUT_MAP(map_name, struct_name, variants)                            \
  /* Event struct definition */                                                \
  struct struct_name {                                                         \
    u64 timestamp;                                                             \
    pid_t pid;                                                                 \
    struct {                                                                   \
      u32 event_type;                                                          \
      union variants;                                                          \
    };                                                                         \
    struct buffer buffer;                                                      \
  };                                                                           \
                                                                               \
  static __always_inline struct struct_name *struct_name##_init(               \
      int event_variant) {                                                     \
    pid_t tgid = interesting_tgid();                                           \
    if (tgid < 0)                                                              \
      return NULL;                                                             \
                                                                               \
    struct struct_name *event = output_temp();                                 \
    if (!event)                                                                \
      return NULL;                                                             \
                                                                               \
    event->event_type = event_variant;                                         \
    event->timestamp = bpf_ktime_get_ns();                                     \
    event->pid = tgid;                                                         \
    event->buffer.len = 0;                                                     \
    return event;                                                              \
  }                                                                            \
                                                                               \
  /* Output map definition */                                                  \
  struct bpf_map_def_aya SEC("maps/events") map_name = {                       \
      .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,                                   \
      .key_size = sizeof(int),                                                 \
      .value_size = sizeof(u32),                                               \
      .max_entries = 0,                                                        \
  };

// The BPF stack limit of 512 bytes is exceeded by network_event,
// so we use a per-cpu array as a workaround
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, char[BUFFER_MAX * 2]);
  __uint(max_entries, 1);
} temp_map SEC(".maps");

// The init map contains configuration status for the eBPF program:
// - The STATUS_INITIALIZED entry indicates the perf event array initialization
//   status. On startup it's set to 0, when the userspace program opens the perf
//   event array it's set to 1. The eBPF program emits events only when it's 1.
#define STATUS_INITIALIZED 0
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 1);
} init_map SEC(".maps");

// Get the temporary buffer inside temp_map as a void pointer, this can be cast
// to the required event type and filled before submitting it for output. The
// pointed at memory contiains BUFFER_MAX *2 bytes.
static __always_inline void *output_temp() {
  u32 key = 0;
  void *event = bpf_map_lookup_elem(&temp_map, &key);
  if (!event) {
    LOG_ERROR("can't get event memory");
    return 0;
  }
  return event;
}

static __always_inline void output_event(void *ctx, void *output_map,
                                         void *event, int struct_len,
                                         int buffer_len) {
  u32 key = STATUS_INITIALIZED;
  u32 *initialization_status = bpf_map_lookup_elem(&init_map, &key);
  if (!initialization_status || !*initialization_status) {
    // The userspace is not ready yet for events on the perf event array
    return;
  }

  // The output size is the full struct length, minus the unused buffer len
  unsigned int len = struct_len - (BUFFER_MAX - buffer_len);
  if (len > 0 && len <= struct_len) {
    int ret = bpf_perf_event_output(ctx, output_map, BPF_F_CURRENT_CPU, event,
                                    len & (BUFFER_MAX - 1));
    if (ret) {
      LOG_ERROR("error %d emitting event of len %d", ret, len);
    }
  }
}
