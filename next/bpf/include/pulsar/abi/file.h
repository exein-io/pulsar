/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
// Records of the file producer (probes/file.bpf.c). See pulsar/abi.h.
// All kinds have variable size.
#pragma once

#include "pulsar/abi.h"

enum pulsar_file_kind {
  PULSAR_FILE_CREATED = 1,
  PULSAR_FILE_DELETED = 2,
  PULSAR_FILE_DIR_CREATED = 3,
  PULSAR_FILE_DIR_DELETED = 4,
  PULSAR_FILE_OPENED = 5,
  PULSAR_FILE_LINK = 6,
  PULSAR_FILE_RENAME = 7,
};

// Body of PULSAR_FILE_CREATED, _DELETED, _DIR_CREATED and _DIR_DELETED.
struct pulsar_file_path {
  struct pulsar_buffer_index path;
};

struct pulsar_file_path_record {
  struct pulsar_record_header header;
  struct pulsar_file_path body;
  struct pulsar_tail tail;
};

struct pulsar_file_opened {
  struct pulsar_buffer_index filename;
  // O_* flags of the open.
  __u32 flags;
};

struct pulsar_file_opened_record {
  struct pulsar_record_header header;
  struct pulsar_file_opened body;
  struct pulsar_tail tail;
};

// pulsar_file_link.flags
#define PULSAR_FILE_LINK_HARD (1u << 0)

struct pulsar_file_link {
  struct pulsar_buffer_index source;
  struct pulsar_buffer_index destination;
  __u32 flags;
};

struct pulsar_file_link_record {
  struct pulsar_record_header header;
  struct pulsar_file_link body;
  struct pulsar_tail tail;
};

struct pulsar_file_rename {
  struct pulsar_buffer_index source;
  struct pulsar_buffer_index destination;
};

struct pulsar_file_rename_record {
  struct pulsar_record_header header;
  struct pulsar_file_rename body;
  struct pulsar_tail tail;
};
