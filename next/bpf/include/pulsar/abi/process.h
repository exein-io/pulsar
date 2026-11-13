/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
// Records of the process producer (probes/process.bpf.c). See pulsar/abi.h.
#pragma once

#include "pulsar/abi.h"

enum pulsar_process_kind {
  PULSAR_PROCESS_FORK = 1,
  PULSAR_PROCESS_EXEC = 2,
  PULSAR_PROCESS_EXIT = 3,
  PULSAR_PROCESS_CHANGE_PARENT = 4,
  PULSAR_PROCESS_CREDS_CHANGE = 5,
};

// `missing` bits of fork and exec.
#define PULSAR_PROCESS_MISSING_NAMESPACES (1u << 0)
#define PULSAR_PROCESS_MISSING_CONTAINER (1u << 1)

struct pulsar_namespaces {
  __u32 uts;
  __u32 ipc;
  __u32 mnt;
  __u32 pid;
  __u32 net;
  __u32 time;
  __u32 cgroup;
};

enum pulsar_container_engine {
  PULSAR_CONTAINER_NONE = 0,
  PULSAR_CONTAINER_DOCKER = 1,
  PULSAR_CONTAINER_PODMAN = 2,
};

#define PULSAR_CONTAINER_NAME_MAX 72

// The cgroup node that names the container. The container id starts at
// `id_offset` in `name` and ends at the first NUL.
struct pulsar_container {
  // enum pulsar_container_engine
  __u32 engine;
  __u32 id_offset;
  __u8 name[PULSAR_CONTAINER_NAME_MAX];
};

// Fixed size. The subject is the child.
struct pulsar_process_fork {
  __u32 missing;
  struct pulsar_namespaces namespaces;
  struct pulsar_container container;
};

struct pulsar_process_fork_record {
  struct pulsar_record_header header;
  struct pulsar_process_fork body;
};

// Variable size. `filename` is the path of the executable, `argv` the
// arguments separated by NUL.
struct pulsar_process_exec {
  __u32 missing;
  __u32 argc;
  struct pulsar_buffer_index filename;
  struct pulsar_buffer_index argv;
  struct pulsar_namespaces namespaces;
  struct pulsar_container container;
};

struct pulsar_process_exec_record {
  struct pulsar_record_header header;
  struct pulsar_process_exec body;
  struct pulsar_tail tail;
};

// Fixed size.
struct pulsar_process_exit {
  __u32 exit_code;
};

struct pulsar_process_exit_record {
  struct pulsar_record_header header;
  struct pulsar_process_exit body;
};

// Fixed size. The subject is the orphan, `ppid` its new parent.
struct pulsar_process_change_parent {
  __u32 ppid;
};

struct pulsar_process_change_parent_record {
  struct pulsar_record_header header;
  struct pulsar_process_change_parent body;
};

// Fixed size. The new credentials; the subject still has the old ones.
struct pulsar_process_creds_change {
  __u32 uid;
  __u32 gid;
};

struct pulsar_process_creds_change_record {
  struct pulsar_record_header header;
  struct pulsar_process_creds_change body;
};
