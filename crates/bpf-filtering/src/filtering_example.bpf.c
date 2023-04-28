#include "common.bpf.h"
#include "interest_tracking.bpf.h"

MAP_RULES(m_rules);
MAP_INTEREST(m_interest, PINNING_DISABLED);

SEC("raw_tracepoint/sched_process_fork")
int BPF_PROG(process_fork, struct task_struct *parent,
             struct task_struct *child) {
  tracker_fork(&m_interest, parent, child);
  return 0;
}

SEC("raw_tracepoint/sched_process_exec")
int BPF_PROG(sched_process_exec, struct task_struct *p, pid_t old_pid,
             struct linux_binprm *bprm) {
  tracker_check_rules(&m_interest, &m_rules, p, BPF_CORE_READ(bprm, filename));
  return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int BPF_PROG(process_exit, struct task_struct *p) {
  tracker_remove(&m_interest, p);
  return 0;
}

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, pid_t);
  __type(value, u64);
  __uint(max_entries, 10);
} skipped_map SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx) {
  pid_t tgid = tracker_interesting_tgid(&m_interest);
  if (tgid < 0) {
    pid_t real_tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("ignoring %d", real_tgid);
    u64 *skipped_counter = bpf_map_lookup_elem(&skipped_map, &real_tgid);
    if (skipped_counter) {
      *skipped_counter += 1;
    }
    return 0;
  }
  // do stuff
  return 0;
}
