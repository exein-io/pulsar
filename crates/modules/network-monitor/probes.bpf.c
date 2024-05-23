// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "buffer.bpf.h"
#include "common.bpf.h"
#include "interest_tracking.bpf.h"
#include "iov_iter_compat.h"
#include "network.bpf.h"
#include "output.bpf.h"
#include "task.bpf.h"

char LICENSE[] SEC("license") = "GPL v2";

#define ADDR_SIZE 16
#define EVENT_BIND 0
#define EVENT_LISTEN 1
#define EVENT_CONNECT 2
#define EVENT_ACCEPT 3
#define EVENT_SEND 4
#define EVENT_RECV 5
#define EVENT_CLOSE 6

#define MAX_DATA_SIZE 4096

struct address {
  u8 ip_ver;
  union {
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
  };
};

struct bind_event {
  struct address addr;
  u8 proto;
};

struct connect_event {
  struct address destination;
  u8 proto;
};

struct accept_event {
  struct address source;
  struct address destination;
};

struct msg_event {
  struct address source;
  struct address destination;
  struct buffer_index data;
  u32 data_len;
  u8 proto;
};

struct close_event {
  pid_t original_pid;
  struct address source;
  struct address destination;
};

struct arguments {
  void *data[3];
};

GLOBAL_INTEREST_MAP_DECLARATION;

OUTPUT_MAP(network_event, {
  struct bind_event bind;
  struct address listen;
  struct connect_event connect;
  struct accept_event accept;
  struct msg_event send;
  struct msg_event recv;
  struct close_event close;
});

// Map a socket pointer to its creating process
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct sock *);
  __type(value, pid_t);
  __uint(max_entries, 10240);
} tcp_set_state_map SEC(".maps");

// Maps for sharing data between various hook points
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct arguments);
  __uint(max_entries, 1024);
} args_map SEC(".maps");

const int IPV6_NUM_OCTECTS = 16;
const int IPV4_NUM_OCTECTS = 4;

// Copy an address from a sockaddr
static __always_inline void copy_sockaddr(struct sockaddr *addr,
                                          struct address *dest,
                                          bool is_user_memory) {
  int r;

  u16 family = 0;
  if (is_user_memory)
    r = bpf_core_read_user(&family, sizeof(family), &addr->sa_family);
  else
    r = bpf_core_read(&family, sizeof(family), &addr->sa_family);
  if (r != 0) {
    LOG_ERROR("Error reading sockaddr family: %d", r);
    return;
  }

  switch (family) {
  case AF_INET: {
    dest->ip_ver = 0;
    if (is_user_memory)
      r = bpf_core_read_user(&dest->v4, sizeof(struct sockaddr_in), addr);
    else
      r = bpf_core_read(&dest->v4, sizeof(struct sockaddr_in), addr);
    if (r != 0) {
      LOG_ERROR("Error copying sockaddr_in: %d", r);
    }
    break;
  }
  case AF_INET6: {
    dest->ip_ver = 1;
    if (is_user_memory)
      r = bpf_core_read_user(&dest->v6, sizeof(struct sockaddr_in6), addr);
    else
      r = bpf_core_read(&dest->v6, sizeof(struct sockaddr_in6), addr);
    if (r != 0) {
      LOG_ERROR("Error copying sockaddr_in6: %d", r);
    }
    break;
  }
  default:
    LOG_DEBUG("ignored sockaddr family %d", family);
  }
}

// Unused fields must be memset to 0 or we could still have garbage from
// previous usages of temp memory.
static void reset_unused_fields_v4(struct sockaddr_in *v4) {
  __builtin_memset(v4->__pad, 0, sizeof(v4->__pad));
}

static void reset_unused_fields_v6(struct sockaddr_in6 *v6) {
  v6->sin6_flowinfo = 0;
  v6->sin6_scope_id = 0;
}

// Copy an address from the source part of sock_common
static __always_inline void copy_skc_source(struct sock_common *sk,
                                            struct address *addr) {
  u16 family = BPF_CORE_READ(sk, skc_family);
  ((struct sockaddr *)&addr->v4)->sa_family = family;
  // port is big endian
  u16 port = __bpf_ntohs(BPF_CORE_READ(sk, skc_num));
  switch (family) {
  case AF_INET: {
    addr->ip_ver = 0;
    addr->v4.sin_port = port;
    bpf_core_read(&addr->v4.sin_addr, IPV4_NUM_OCTECTS, &sk->skc_rcv_saddr);
    reset_unused_fields_v4(&addr->v4);
    break;
  }
  case AF_INET6: {
    addr->ip_ver = 1;
    addr->v6.sin6_port = port;
    bpf_core_read(&addr->v6.sin6_addr, IPV6_NUM_OCTECTS,
                  &sk->skc_v6_rcv_saddr.in6_u.u6_addr32);
    reset_unused_fields_v6(&addr->v6);
    break;
  }
  default:
    LOG_DEBUG("ignored sockaddr family %d", family);
  }
}

// Copy an address from the destination part of sock_common
static __always_inline void copy_skc_dest(struct sock_common *sk,
                                          struct address *addr) {
  u16 family = BPF_CORE_READ(sk, skc_family);
  ((struct sockaddr *)&addr->v4)->sa_family = family;
  switch (family) {
  case AF_INET: {
    addr->ip_ver = 0;
    bpf_core_read(&addr->v4.sin_port, sizeof(u16), &sk->skc_dport);
    bpf_core_read(&addr->v4.sin_addr, IPV4_NUM_OCTECTS, &sk->skc_daddr);
    reset_unused_fields_v4(&addr->v4);
    break;
  }
  case AF_INET6: {
    addr->ip_ver = 1;
    bpf_core_read(&addr->v6.sin6_port, sizeof(u16), &sk->skc_dport);
    bpf_core_read(&addr->v6.sin6_addr, IPV6_NUM_OCTECTS,
                  &sk->skc_v6_daddr.in6_u.u6_addr32);
    reset_unused_fields_v6(&addr->v6);
    break;
  }
  default:
    LOG_DEBUG("ignored sockaddr family %d", family);
  }
}

static __always_inline __u32 tcp_hdrlen(const struct tcphdr *th)
{
  return th->doff << 2;
}

static __always_inline void copy_iphdr_source(struct iphdr *ih,
                                              struct address *addr) {
  addr->ip_ver = 0;
  ((struct sockaddr*)&addr->v4)->sa_family = AF_INET;
  bpf_core_read(&addr->v4.sin_addr, IPV4_NUM_OCTECTS, &ih->saddr);
  reset_unused_fields_v4(&addr->v4);
}

static __always_inline void copy_iphdr_dest(struct iphdr *ih,
                                            struct address *addr) {
  addr->ip_ver = 0;
  ((struct sockaddr*)&addr->v4)->sa_family = AF_INET;
  bpf_core_read(&addr->v4.sin_addr, IPV4_NUM_OCTECTS, &ih->daddr);
  reset_unused_fields_v4(&addr->v4);
}

static __always_inline void copy_ipv6hdr_source(struct ipv6hdr *ih6,
                                                struct address *addr) {
  addr->ip_ver = 1;
  ((struct sockaddr*)&addr->v6)->sa_family = AF_INET6;
  bpf_core_read(&addr->v6.sin6_addr, IPV6_NUM_OCTECTS,
                &ih6->saddr.in6_u.u6_addr32);
  reset_unused_fields_v6(&addr->v6);
}

static __always_inline void copy_ipv6hdr_dest(struct ipv6hdr *ih6,
                                              struct address *addr) {
  addr->ip_ver = 1;
  ((struct sockaddr*)&addr->v6)->sa_family = AF_INET6;
  bpf_core_read(&addr->v6.sin6_addr, IPV6_NUM_OCTECTS,
                &ih6->daddr.in6_u.u6_addr32);
  reset_unused_fields_v6(&addr->v6);
}

static __always_inline void copy_ipv4_tcphdr_source(struct tcphdr *th,
                                                    struct address *addr) {
  addr->v4.sin_port = th->source;
}

static __always_inline void copy_ipv4_tcphdr_dest(struct tcphdr *th,
                                                  struct address *addr) {
  addr->v4.sin_port = th->dest;
}

static __always_inline void copy_ipv6_tcphdr_source(struct tcphdr *th,
                                                    struct address *addr) {
  addr->v6.sin6_port = th->source;
}

static __always_inline void copy_ipv6_tcphdr_dest(struct tcphdr *th,
                                                  struct address *addr) {
  addr->v6.sin6_port = th->dest;
}

static __always_inline void copy_ipv4_udphdr_source(struct udphdr *uh,
                                                    struct address *addr) {
  addr->v4.sin_port = uh->source;
}

static __always_inline void copy_ipv4_udphdr_dest(struct udphdr *uh,
                                                  struct address *addr) {
  addr->v4.sin_port = uh->dest;
}

static __always_inline void copy_ipv6_udphdr_source(struct udphdr *uh,
                                                    struct address *addr) {
  addr->v6.sin6_port = uh->source;
}

static __always_inline void copy_ipv6_udphdr_dest(struct udphdr *uh,
                                                  struct address *addr) {
  addr->v6.sin6_port = uh->dest;
}

static __always_inline u16 get_sock_protocol(struct sock *sk) {
  u64 proto = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);
  // TODO: clean this up
  if (proto == IPPROTO_UDP) {
    return PROTO_UDP;
  } else {
    return PROTO_TCP;
  }
}

PULSAR_LSM_HOOK(socket_bind, struct socket *, sock, struct sockaddr *, address,
                int, addrlen);
void __always_inline on_socket_bind(void *ctx, struct socket *sock,
                                    struct sockaddr *address, int addrlen) {
  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return;
  int ret;
  struct sock *sk = BPF_CORE_READ(sock, sk);
  struct network_event *event = init_network_event(EVENT_BIND, tgid);
  if (!event)
    return;
  copy_sockaddr(address, &event->bind.addr, false);
  event->bind.proto = get_sock_protocol(sk);

  output_network_event(ctx, event);
}

PULSAR_LSM_HOOK(socket_listen, struct socket *, sock, int, backlog);
void __always_inline on_socket_listen(void *ctx, struct socket *sock,
                                      int backlog) {
  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return;
  struct network_event *event = init_network_event(EVENT_LISTEN, tgid);
  if (!event)
    return;
  struct sock *sk = BPF_CORE_READ(sock, sk);
  copy_skc_source(&sk->__sk_common, &event->listen);

  output_network_event(ctx, event);
}

PULSAR_LSM_HOOK(socket_connect, struct socket *, sock, struct sockaddr *,
                address, int, addrlen);
static __always_inline void on_socket_connect(void *ctx, struct socket *sock,
                                              struct sockaddr *address,
                                              int addrlen) {
  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return;
  int ret;
  struct sock *sk = BPF_CORE_READ(sock, sk);
  struct network_event *event = init_network_event(EVENT_CONNECT, tgid);
  if (!event)
    return;
  event->timestamp = bpf_ktime_get_ns();

  copy_sockaddr(address, &event->connect.destination, false);
  event->connect.proto = get_sock_protocol(sk);

  output_network_event(ctx, event);
}

PULSAR_LSM_HOOK(socket_accept, struct socket *, sock, struct socket *, newsock);
static __always_inline void on_socket_accept(void *ctx, struct socket *sock,
                                             struct socket *newsock) {
  // This LSM hook is invoked on accept calls, which happens before
  // there's an actual connection. If we tried to read the source address
  // from newsock, we'd get empty data.
  // For this reason, we'll just save the socket pointer and read it when
  // the accept syscall exits.
  if (tracker_interesting_tgid(&GLOBAL_INTEREST_MAP) >= 0) {
    struct arguments args = {0};
    args.data[0] = newsock;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&args_map, &pid_tgid, &args, BPF_ANY);
  }
}

static __always_inline void on_accept_exit(void *ctx, long ret) {
  // Retrieve the socket pointer saved by on_socket_accept.
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct arguments *args = bpf_map_lookup_elem(&args_map, &pid_tgid);
  if (args == 0) {
    LOG_DEBUG("accept_exit on unknown socket");
    return;
  }
  struct socket *sock = (struct socket *)args->data[0];
  bpf_map_delete_elem(&args_map, &pid_tgid);

  // Ignore failed accept
  if (ret < 0) {
    LOG_DEBUG("Failed accept: %d", ret);
    return;
  }

  // Emit event
  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return;
  struct network_event *event = init_network_event(EVENT_ACCEPT, tgid);
  if (!event)
    return;
  struct sock *sk = BPF_CORE_READ(sock, sk);
  copy_skc_source(&sk->__sk_common, &event->accept.destination);
  copy_skc_dest(&sk->__sk_common, &event->accept.source);
  output_network_event(ctx, event);
}

#define ITER_UBUF 5

static __always_inline void
*get_iov_base(const void *msg_iter) {
  // Definition of `struct iov_iter` used in new kernels (>=6.4).
  const struct iov_iter *msg_iter_nocompat = msg_iter;

  // Check if `msg_iter` matches the new definition of `struct iov_iter`. The
  // `__ubuf_iovec` field doesn't exist in kernels <= 6.4.
  if (bpf_core_field_exists(msg_iter_nocompat->__ubuf_iovec)) {
    if (BPF_CORE_READ(msg_iter_nocompat, iter_type) == ITER_UBUF) {
      return BPF_CORE_READ(msg_iter_nocompat, __ubuf_iovec.iov_base);
    }
    return BPF_CORE_READ(msg_iter_nocompat, __iov, iov_base);
  }

  // Use the <= 6.4 definition, which we represent with `struct iov_iter_compat`.
  const struct iov_iter_compat *msg_iter_compat = msg_iter;
  return BPF_CORE_READ(msg_iter_compat, iov, iov_base);
}

SEC("kprobe/tcp_set_state")
int tcp_set_state(struct pt_regs *regs) {
  pid_t tgid = bpf_get_current_pid_tgid() >> 32;
  // this function may be called after the process has already exited,
  // so we don't want to log errors in case tgid has already been
  // deleted from map_interest
  if (!tracker_is_interesting(&GLOBAL_INTEREST_MAP, tgid, __func__, false,
                              true))
    return 0;

  int ret;
  struct sock *sk = (struct sock *)PT_REGS_PARM1(regs);
  int state = (int)PT_REGS_PARM2(regs);
  if (state == TCP_SYN_SENT || state == TCP_LAST_ACK) {
    ret = bpf_map_update_elem(&tcp_set_state_map, &sk, &tgid, BPF_ANY);
    if (ret) {
      LOG_ERROR("updating tcp_set_state_map");
    }
    return 0;
  }
  if (state != TCP_CLOSE)
    return 0;
  pid_t *id = bpf_map_lookup_elem(&tcp_set_state_map, &sk);
  pid_t original_pid = tgid;
  if (!id) {
    LOG_DEBUG("can't retrieve the original pid");
    return 0;
  } else {
    original_pid = *id;
  }
  ret = bpf_map_delete_elem(&tcp_set_state_map, &sk);
  if (ret) {
    LOG_ERROR("deleting from tcp_set_state_map");
  }

  u16 family = 0;
  bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family);
  short ipver = family == AF_INET ? 4 : 6;
  u32 key = 0;

  struct network_event *event = init_network_event(EVENT_CLOSE, tgid);
  if (!event)
    return 0;
  event->close.original_pid = original_pid;
  copy_skc_source(&sk->__sk_common, &event->close.source);
  copy_skc_dest(&sk->__sk_common, &event->close.destination);

  output_network_event(regs, event);
  return 0;
}

// Tracepoints

SEC("tracepoint/sys_exit_accept4")
int BPF_PROG(sys_exit_accept4, struct pt_regs *regs, int __syscall_nr,
             long ret) {
  // NOTE: this gets called even if the process is stopped with a kill -9,
  // there is no need to intercept sched_process_exit for map cleanup.
  on_accept_exit(ctx, ret);
  return 0;
}

SEC("tracepoint/sys_exit_accept")
int BPF_PROG(sys_exit_accept, struct pt_regs *regs, int __syscall_nr,
             long ret) {
  // NOTE: this gets called even if the process is stopped with a kill -9,
  // there is no need to intercept sched_process_exit for map cleanup.
  on_accept_exit(ctx, ret);
  return 0;
}

__always_inline int process_skb(struct __sk_buff *skb,
                                __u8 direction) {
  struct task_struct *task = get_current_task();
  pid_t tgid = BPF_CORE_READ(task, tgid);

  if (!tracker_is_interesting(&GLOBAL_INTEREST_MAP, tgid, __func__, true,
                              true))
    return CGROUP_SKB_OK;

  struct network_event *network_event;
  switch (direction) {
  case EGRESS:
    network_event = init_network_event(EVENT_SEND, tgid);
    break;
  case INGRESS:
    network_event = init_network_event(EVENT_RECV, tgid);
    break;
  }
  if (!network_event)
    return CGROUP_SKB_OK;

  struct msg_event *msg_event;
  switch (direction) {
  case EGRESS:
    msg_event = &network_event->send;
    break;
  case INGRESS:
    msg_event = &network_event->recv;
    break;
  }

  __u32 headers_len;
  __be16 l3_proto = bpf_htons(skb->protocol);
  __u8 l4_proto;

  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;

  // Parse L3 header (IPv4 / IPv6).
  switch (l3_proto) {
  case ETH_P_IPV4: {
    if (data + sizeof(struct iphdr) > data_end) {
      LOG_ERROR("found an IPv4 packet too small to fit an IP header");
      goto pass;
    }

    struct iphdr *ih = data;
    l4_proto = ih->protocol;

    switch (direction) {
    case EGRESS:
      copy_iphdr_source(ih, &msg_event->source);
      copy_iphdr_dest(ih, &msg_event->destination);
      break;
    case INGRESS:
      copy_iphdr_source(ih, &msg_event->destination);
      copy_iphdr_dest(ih, &msg_event->source);
      break;
    }

    msg_event->proto = l4_proto;
    headers_len = sizeof(struct iphdr);

    break;
  }
  case ETH_P_IPV6: {
    if (data + sizeof(struct ipv6hdr) > data_end) {
      LOG_ERROR("found an IPv6 packet too small to fit an IP header");
      goto pass;
    }

    struct ipv6hdr *ih6 = data;
    l4_proto = ih6->nexthdr;

    switch (direction) {
    case EGRESS:
      copy_ipv6hdr_source(ih6, &msg_event->source);
      copy_ipv6hdr_dest(ih6, &msg_event->destination);
      break;
    case INGRESS:
      copy_ipv6hdr_source(ih6, &msg_event->destination);
      copy_ipv6hdr_dest(ih6, &msg_event->source);
      break;
    }

    msg_event->proto = l4_proto;
    headers_len = sizeof(struct ipv6hdr);

    break;
  }
  default:
    LOG_DEBUG("ignored unsupported L3 protocol %d", l3_proto);
    goto pass;
  }
  
  // Parse L4 header (ICMP / TCP / UDP).
  switch (l4_proto) {
  case IPPROTO_ICMP:
    headers_len += sizeof(struct icmphdr);
    break;
  case IPPROTO_TCP: {
    if (data + headers_len + sizeof(struct tcphdr) > data_end) {
      LOG_ERROR("found a TCP packet too small to fit a TCP header");
      goto pass;
    }

    struct tcphdr *th = data + headers_len;
    headers_len += tcp_hdrlen(th);

    switch (l3_proto) {
    case ETH_P_IPV4:
      switch (direction) {
      case EGRESS:
        copy_ipv4_tcphdr_source(th, &msg_event->source);
        copy_ipv4_tcphdr_dest(th, &msg_event->destination);
        break;
      case INGRESS:
        copy_ipv4_tcphdr_source(th, &msg_event->destination);
        copy_ipv4_tcphdr_dest(th, &msg_event->source);
        break;
      }
      break;
    case ETH_P_IPV6:
      switch (direction) {
      case EGRESS:
        copy_ipv6_tcphdr_source(th, &msg_event->source);
        copy_ipv6_tcphdr_dest(th, &msg_event->destination);
        break;
      case INGRESS:
        copy_ipv6_tcphdr_source(th, &msg_event->destination);
        copy_ipv6_tcphdr_dest(th, &msg_event->source);
        break;
      }
    }
    break;
  }
  case IPPROTO_UDP: {
    if (data + headers_len + sizeof(struct udphdr) > data_end) {
      LOG_ERROR("found a UDP packet too small to fit a UDP header");
      goto pass;
    }

    struct udphdr *uh = data + headers_len;
    headers_len += sizeof(struct udphdr);

    switch (l3_proto) {
    case ETH_P_IPV4:
      switch (direction) {
      case EGRESS:
        copy_ipv4_udphdr_source(uh, &msg_event->source);
        copy_ipv4_udphdr_dest(uh, &msg_event->destination);
        break;
      case INGRESS:
        copy_ipv4_udphdr_source(uh, &msg_event->destination);
        copy_ipv4_udphdr_dest(uh, &msg_event->source);
        break;
      }
      break;
    case ETH_P_IPV6:
      switch (direction) {
      case EGRESS:
        copy_ipv6_udphdr_source(uh, &msg_event->source);
        copy_ipv6_udphdr_dest(uh, &msg_event->destination);
        break;
      case INGRESS:
        copy_ipv6_udphdr_source(uh, &msg_event->destination);
        copy_ipv6_udphdr_dest(uh, &msg_event->source);
        break;
      }
      break;
    }

    buffer_index_init(&network_event->buffer, &msg_event->data);
    if (buffer_append_skb_bytes(&network_event->buffer, &msg_event->data, skb,
                                headers_len) < 0) {
      LOG_ERROR("Failed to retrieve the packet payload. The event is going to miss the `data` part.");
    }
    break;
  }
  default:
    LOG_DEBUG("ignored unsupported L4 protocol %d", l4_proto);
    goto send_event;
  }

  msg_event->data_len = skb->len - headers_len;

send_event:
  output_network_event(skb, network_event);
pass:
  return CGROUP_SKB_OK;
}

SEC("cgroup_skb/egress")
int skb_egress(struct __sk_buff *skb) {
  return process_skb(skb, EGRESS);
}

SEC("cgroup_skb/ingress")
int skb_ingress(struct __sk_buff *skb) {
  return process_skb(skb, INGRESS);
}
