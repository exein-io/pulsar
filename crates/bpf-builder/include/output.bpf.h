/// Manage output to userspace using a perf event array map
#pragma once

#include "bpf/bpf_helpers.h"
#include "buffer.bpf.h"
#include "interest_tracking.bpf.h"

// eBPF programs could interrupt each other, see "Are BPF programs preemptible?"
// thread on the kernel BPF mailing list:
// https://lore.kernel.org/bpf/878rhty100.fsf@cloudflare.com/T/#t
#define MAX_PREEMPTION_NESTING_LEVEL 3

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
      int event_variant, struct bpf_map_def_aya *tracker) {                    \
    pid_t tgid = tracker_interesting_tgid(tracker);                            \
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
  struct {                                                                     \
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);                               \
    __type(key, int);                                                          \
    __type(value, u32);                                                        \
    __uint(max_entries, 0);                                                    \
  } map_name SEC(".maps");

// The BPF stack limit of 512 bytes is exceeded by network_event,
// so we use a per-cpu array as a workaround
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, char[BUFFER_MAX * 2]);
  __uint(max_entries, MAX_PREEMPTION_NESTING_LEVEL);
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

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, u64);
  __uint(max_entries, 1);
} nesting_counter_map SEC(".maps");

static __always_inline int increase_nesting() {
  u32 zero = 0;
  u64 *nesting_level = bpf_map_lookup_elem(&nesting_counter_map, &zero);
  if (!nesting_level) {
    LOG_ERROR("can't get nesting counter");
    return -1;
  }
#ifdef FEATURE_NO_FN_POINTERS
  u64 counter = *nesting_level;
  *nesting_level += 1;
#else
  u64 counter = __sync_fetch_and_add(nesting_level, 1);
#endif
  if (counter > 0) {
    LOG_ERROR("nesting_level = %d", counter + 1);
  }
  return counter;
}

static __always_inline int decrease_nesting() {
  u32 zero = 0;
  u64 *nesting_level = bpf_map_lookup_elem(&nesting_counter_map, &zero);
  if (nesting_level) {
#ifdef FEATURE_NO_FN_POINTERS
    *nesting_level -= 1;
    return *nesting_level;
#else
    return __sync_fetch_and_sub(nesting_level, 1);
#endif
  } else {
    return -1;
  }
}

// Get the temporary buffer inside temp_map as a void pointer, this can be cast
// to the required event type and filled before submitting it for output. The
// pointed at memory contiains BUFFER_MAX *2 bytes.
static __always_inline void *output_temp() {
  int nesting_level = increase_nesting();
  if (nesting_level < 0) {
    LOG_ERROR("invalid nesting_level");
    return NULL;
  }
  u32 key = nesting_level;
  void *event = bpf_map_lookup_elem(&temp_map, &key);
  if (!event) {
    LOG_ERROR("can't get event memory");
    return NULL;
  }
  return event;
}

static __always_inline void output_event(void *ctx, void *output_map,
                                         void *event, int struct_len,
                                         int buffer_len) {
  decrease_nesting();

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
