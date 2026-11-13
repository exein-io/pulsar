/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
// Records of the network producer (probes/network.bpf.c). See pulsar/abi.h.
#pragma once

#include "pulsar/abi.h"

enum pulsar_network_kind {
  PULSAR_NETWORK_BIND = 1,
  PULSAR_NETWORK_LISTEN = 2,
  PULSAR_NETWORK_CONNECT = 3,
  PULSAR_NETWORK_ACCEPT = 4,
  PULSAR_NETWORK_SEND = 5,
  PULSAR_NETWORK_RECEIVE = 6,
  PULSAR_NETWORK_CLOSE = 7,
};

// `missing` bits: an address that could not be read.
#define PULSAR_NETWORK_MISSING_SOURCE (1u << 0)
#define PULSAR_NETWORK_MISSING_DESTINATION (1u << 1)

#define PULSAR_ADDRESS_MAX 16

struct pulsar_address {
  // AF_INET or AF_INET6.
  __u16 family;
  // Network byte order.
  __u16 port;
  // AF_INET6 only.
  __u32 scope_id;
  // AF_INET uses the first 4 bytes.
  __u8 addr[PULSAR_ADDRESS_MAX];
};

// Fixed size. Bind and listen report their address as the source.
struct pulsar_network_bind {
  __u32 missing;
  // IPPROTO_*
  __u32 proto;
  struct pulsar_address source;
};

struct pulsar_network_bind_record {
  struct pulsar_record_header header;
  struct pulsar_network_bind body;
};

// Fixed size.
struct pulsar_network_listen {
  __u32 missing;
  struct pulsar_address source;
};

struct pulsar_network_listen_record {
  struct pulsar_record_header header;
  struct pulsar_network_listen body;
};

// Fixed size.
struct pulsar_network_connect {
  __u32 missing;
  // IPPROTO_*
  __u32 proto;
  struct pulsar_address destination;
};

struct pulsar_network_connect_record {
  struct pulsar_record_header header;
  struct pulsar_network_connect body;
};

// Fixed size. Body of PULSAR_NETWORK_ACCEPT and PULSAR_NETWORK_CLOSE.
struct pulsar_network_connection {
  __u32 missing;
  struct pulsar_address source;
  struct pulsar_address destination;
};

struct pulsar_network_connection_record {
  struct pulsar_record_header header;
  struct pulsar_network_connection body;
};

// Variable size. Body of PULSAR_NETWORK_SEND and PULSAR_NETWORK_RECEIVE.
// `data` holds the start of the payload, `data_len` is its full length.
struct pulsar_network_message {
  __u32 missing;
  // IPPROTO_*
  __u32 proto;
  struct pulsar_address source;
  struct pulsar_address destination;
  struct pulsar_buffer_index data;
  __u32 data_len;
};

struct pulsar_network_message_record {
  struct pulsar_record_header header;
  struct pulsar_network_message body;
  struct pulsar_tail tail;
};
