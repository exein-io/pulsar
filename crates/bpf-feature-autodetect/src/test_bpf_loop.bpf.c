#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

static int callback(void *ctx, u32 index) {
  return 0;
}

SEC("tracepoint")
int probe_bpf_loop(void *ctx) {
  bpf_loop(5, callback, NULL, 0);
  return 0;
}
