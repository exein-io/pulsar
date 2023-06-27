/// Manage output to userspace using a perf event array map
#pragma once

#include "bpf/bpf_helpers.h"
#include "buffer.bpf.h"
#include "compatibility.bpf.h"
#include "interest_tracking.bpf.h"

// eBPF programs could interrupt each other, see "Are BPF programs preemptible?"
// thread on the kernel BPF mailing list:
// https://lore.kernel.org/bpf/878rhty100.fsf@cloudflare.com/T/#t
#define MAX_PREEMPTION_NESTING_LEVEL 3

#define OUTPUT_MAP(struct_name, variants)                                      \
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
  /* The BPF stack limit of 512 bytes is exceeded by network_event,*/          \
  /* so we use a per-cpu array as a workaround*/                               \
  struct {                                                                     \
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                                   \
    __type(key, u32);                                                          \
    __type(value, struct struct_name);                                         \
    __uint(max_entries, MAX_PREEMPTION_NESTING_LEVEL);                         \
  } map_temp_##struct_name SEC(".maps");                                       \
                                                                               \
  struct {                                                                     \
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                                   \
    __type(key, u32);                                                          \
    __type(value, u64);                                                        \
    __uint(max_entries, 1);                                                    \
  } map_nesting_##struct_name SEC(".maps");                                    \
                                                                               \
  static __always_inline void decrease_nesting_##struct_name() {               \
    u32 zero = 0;                                                              \
    u64 *nesting_level =                                                       \
        bpf_map_lookup_elem(&map_nesting_##struct_name, &zero);                \
    if (!nesting_level) {                                                      \
      LOG_ERROR("can't get nesting counter");                                  \
      return;                                                                  \
    }                                                                          \
    u64 old_value = sync_decrement(nesting_level);                             \
    if (old_value <= 0) {                                                      \
      LOG_ERROR("nesting_level = %d before decrement", old_value);             \
      sync_increment(nesting_level);                                           \
    }                                                                          \
  }                                                                            \
                                                                               \
  static __always_inline int increase_nesting_##struct_name() {                \
    u32 zero = 0;                                                              \
    u64 *nesting_level =                                                       \
        bpf_map_lookup_elem(&map_nesting_##struct_name, &zero);                \
    if (!nesting_level) {                                                      \
      LOG_ERROR("can't get nesting counter");                                  \
      return -1;                                                               \
    }                                                                          \
    u64 old_value = sync_increment(nesting_level);                             \
    if (old_value > 0) {                                                       \
      /*This is not an error, but being so uncommon, it may sill make sense to \
       * log it */                                                             \
      LOG_DEBUG("Preemption actually happend: nesting_level = %d",             \
                old_value + 1);                                                \
    }                                                                          \
    if (old_value >= MAX_PREEMPTION_NESTING_LEVEL) {                           \
      LOG_ERROR("nesting_level = %d", old_value);                              \
      sync_decrement(nesting_level);                                           \
      return -1;                                                               \
    }                                                                          \
    return old_value;                                                          \
  }                                                                            \
                                                                               \
  static __always_inline struct struct_name *init_##struct_name(               \
      int event_variant, pid_t tgid) {                                         \
    int nesting_level = increase_nesting_##struct_name();                      \
    if (nesting_level < 0) {                                                   \
      LOG_ERROR("invalid nesting_level");                                      \
      return NULL;                                                             \
    }                                                                          \
    u32 key = nesting_level;                                                   \
    struct struct_name *event =                                                \
        bpf_map_lookup_elem(&map_temp_##struct_name, &key);                    \
    if (!event) {                                                              \
      LOG_ERROR("can't get event memory for nesting level %d", nesting_level); \
      return NULL;                                                             \
    }                                                                          \
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
    /* These are irrelevant for perf event arrays: */                          \
    __type(key, int);                                                          \
    __type(value, int);                                                        \
  } map_output_##struct_name SEC(".maps");                                     \
                                                                               \
  static __always_inline void output_##struct_name(                            \
      void *ctx, struct struct_name *event) {                                  \
    decrease_nesting_##struct_name();                                          \
    if (is_initialized()) {                                                    \
      if (event->buffer.len >= BUFFER_MAX) {                                   \
        LOG_ERROR("invalid buffer.len = %d, skipping event",                   \
                  event->buffer.len);                                          \
        return;                                                                \
      }                                                                        \
      /* The output size is the full struct length,                            \
       * minus the unused buffer len*/                                         \
      unsigned int len =                                                       \
          sizeof(struct struct_name) - (BUFFER_MAX - event->buffer.len);       \
      int ret = bpf_perf_event_output(ctx, &map_output_##struct_name,          \
                                      BPF_F_CURRENT_CPU, event, len);          \
      if (ret) {                                                               \
        LOG_ERROR("error %d emitting event of len %d", ret, len);              \
      }                                                                        \
    }                                                                          \
  }

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

// Return if the userspace is ready for events on the perf event array
static __always_inline int is_initialized() {
  u32 key = STATUS_INITIALIZED;
  u32 *initialization_status = bpf_map_lookup_elem(&init_map, &key);
  return initialization_status && *initialization_status;
}

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

// Decremnet value by one
static __always_inline u64 sync_decrement(u64 *value) {
#ifdef FEATURE_ATOMICS
  return __sync_fetch_and_sub(value, 1);
#else
  u64 old_value = *value;
  *value -= 1;
  return old_value;
#endif
}
