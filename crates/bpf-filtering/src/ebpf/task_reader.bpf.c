// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "interest_tracking.bpf.h"

uint32_t tid = 0;
int num_unknown_tid = 0;
int num_known_tid = 0;

SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	static char info[] = "    === END ===";

	if (task == NULL) {
		BPF_SEQ_PRINTF(seq, "%s\n", info);
		return 0;
	}

	if (task->pid != (pid_t)tid)
		num_unknown_tid++;
	else
		num_known_tid++;

	if (ctx->meta->seq_num == 0)
		BPF_SEQ_PRINTF(seq, "    tgid      gid\n");

	BPF_SEQ_PRINTF(seq, "%8d %8d\n", task->tgid, task->pid);
	return 0;
}
