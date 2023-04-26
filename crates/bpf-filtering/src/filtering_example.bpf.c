#include "common.bpf.h"
#include "interest_tracking.bpf.h"

MAP_RULES(m_rules);
MAP_INTEREST(m_interest, false);

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

SEC("tracepoint/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx) {
  pid_t tgid = tracker_interesting_tgid(&m_interest);
  if (tgid < 0)
    return 0;
  // do stuff
  return 0;
}
