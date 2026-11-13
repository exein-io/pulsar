/* SPDX-License-Identifier: GPL-2.0-only */

#pragma once

// Return statuses of cgroup_skb programs.

// Accept the packet in the cgroup_skb program.
#define CGROUP_SKB_OK 1
// Deny the packet in the cgroup_skb program.
#define CGROUP_SKB_SHOT 0

// EtherTypes (indicating which protocol is encapsulated in the payload of the
// Ethernet frame).

// IPv4 EtherType.
#define ETH_P_IPV4 0x0800
// IPv6 EtherType.
#define ETH_P_IPV6 0x86DD

// Protocols encapsulated in the IP(v4/v6) payload.

// TCP protocol.
#define PROTO_TCP 0
// UDP protocol.
#define PROTO_UDP 1

// Address families

// Unix domain sockets.
#define AF_UNIX 1
// POSIX name for AF_UNIX.
#define AF_LOCAL 1
// IPv4 address family.
#define AF_INET 2
// IPv6 address family.
#define AF_INET6 10

// Traffic direction.
#define EGRESS 0
#define INGRESS 1
