/* SPDX-License-Identifier: GPL-2.0-only */

#pragma once

#include "common.bpf.h"

static __always_inline struct task_struct *get_current_task() {
#ifdef FEATURE_TASK_BTF
  return bpf_get_current_task_btf();
#else
  return (struct task_struct*)bpf_get_current_task();
#endif
}
