// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "buffer.bpf.h"
#include "common.bpf.h"
#include "interest_tracking.bpf.h"
#include "output.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ADDR_SIZE 16
#define EVENT_BIND 0
#define EVENT_LISTEN 1
#define EVENT_CONNECT 2
#define EVENT_ACCEPT 3
#define EVENT_SEND 4
#define EVENT_RECV 5
#define EVENT_CLOSE 6

#define PROTO_TCP 0
#define PROTO_UDP 1

#define AF_UNIX 1   /* Unix domain sockets */
#define AF_LOCAL 1  /* POSIX name for AF_UNIX */
#define AF_INET 2   /* Internet IP Protocol */
#define AF_INET6 10 /* IP version 6 */

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
  struct network_event *event = init_network_event(EVENT_BIND, tgid);
  if (!event)
    return;
  copy_sockaddr(address, &event->bind.addr, false);
  event->bind.proto = get_sock_protocol(BPF_CORE_READ(sock, sk));

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
  struct network_event *event = init_network_event(EVENT_CONNECT, tgid);
  if (!event)
    return;
  event->timestamp = bpf_ktime_get_ns();

  copy_sockaddr(address, &event->connect.destination, false);
  event->connect.proto = get_sock_protocol(BPF_CORE_READ(sock, sk));

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

static __always_inline void
read_iovec(struct buffer *buffer, struct msg_event *output, void *iov_base) {
  size_t len = output->data_len;

  unsigned int msg_iter_type = 0;

  if (len > MAX_DATA_SIZE) {
    LOG_DEBUG("len=%d MAX_DATA_SIZE=%d", len, MAX_DATA_SIZE);
  }

  // limit the index to avoid "min value is negative, either use unsigned or
  // 'var &= const'"
  len &= (MAX_DATA_SIZE - 1);

  buffer_index_init(buffer, &output->data);
  buffer_append_user_memory(buffer, &output->data, iov_base, len);
  LOG_DEBUG("get data size %d -> %d", len, len & (MAX_DATA_SIZE - 1));
}

PULSAR_LSM_HOOK(socket_sendmsg, struct socket *, sock, struct msghdr *, msg,
                int, size);
static __always_inline void on_socket_sendmsg(void *ctx, struct socket *sock,
                                              struct msghdr *msg, int size) {
  if (size <= 0)
    return;

  struct sock *sk = BPF_CORE_READ(sock, sk);
  u16 proto = get_sock_protocol(sk);
  void *iov_base = BPF_CORE_READ(msg, msg_iter.iov, iov_base);

  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return;
  struct network_event *event = init_network_event(EVENT_SEND, tgid);
  if (!event)
    return;
  event->send.proto = proto;
  event->send.data_len = size;
  // Copy data only for UDP events since we want to intercept DNS requests
  if (proto == PROTO_UDP) {
    read_iovec(&event->buffer, &event->send, iov_base);
  } else {
    event->send.data.len = 0;
  }

  copy_skc_source(&sk->__sk_common, &event->send.source);
  copy_skc_dest(&sk->__sk_common, &event->send.destination);

  output_network_event(ctx, event);
}

static __always_inline void save_recvmsg_addr(void *ctx,
                                              struct sockaddr *addr) {
  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return;
  struct arguments args = {0};
  args.data[2] = addr;
  u64 pid_tgid = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&args_map, &pid_tgid, &args, BPF_ANY);
}

PULSAR_LSM_HOOK(socket_recvmsg, struct socket *, sock, struct msghdr *, msg,
                int, size, int, flags);
static __always_inline void on_socket_recvmsg(void *ctx, struct socket *sock,
                                              struct msghdr *msg, int size,
                                              int flags) {
  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return;
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct sock *sk = (struct sock *)BPF_CORE_READ(sock, sk);
  void *iov_base = BPF_CORE_READ(msg, msg_iter.iov, iov_base);

  struct arguments args = {0};
  args.data[0] = sk;
  args.data[1] = iov_base;

  struct arguments *old_args = bpf_map_lookup_elem(&args_map, &pid_tgid);
  if (old_args) {
    args.data[2] = old_args->data[2];
  }

  int r = bpf_map_update_elem(&args_map, &pid_tgid, &args, BPF_ANY);
  if (r != 0) {
    LOG_ERROR("insert error on args_map: %d %d", pid_tgid, r);
  } else {
    LOG_DEBUG("insert args_map: %d", pid_tgid);
  }
}

static __always_inline void do_recvmsg(void *ctx, long ret) {
  pid_t tgid = tracker_interesting_tgid(&GLOBAL_INTEREST_MAP);
  if (tgid < 0)
    return;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct arguments *args = bpf_map_lookup_elem(&args_map, &pid_tgid);
  int r = bpf_map_delete_elem(&args_map, &pid_tgid);
  // LOG_DEBUG("delete args_map: %d %d", pid_tgid, r);
  if (!args) {
    return;
  }
  struct sock *sk = (struct sock *)args->data[0];
  void *iov_base = (void *)args->data[1];

  int len = ret;
  if (len <= 0)
    return;

  struct network_event *event = init_network_event(EVENT_RECV, tgid);
  if (!event)
    return;

  u16 proto = get_sock_protocol(sk);
  event->recv.proto = proto;
  event->recv.data_len = len;
  // Copy data only for UDP events since we want to intercept DNS replies
  if (proto == PROTO_UDP) {
    read_iovec(&event->buffer, &event->recv, iov_base);
  } else {
    event->recv.data.len = 0;
  }

  u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

  copy_skc_source(&sk->__sk_common, &event->recv.source);
  if (proto == PROTO_UDP) {
    // in UDP we find destination value in sockaddr
    // NOTE: msg_name is NULL if the userspace code is not interested
    // in knowing the source of the message. In that case we won't extract
    // the source port and address.
    struct sockaddr *addr = args->data[2];
    if (!addr) {
      LOG_DEBUG("sockaddr is null. ");
    } else {
      copy_sockaddr(addr, &event->recv.destination, true);
    }
  } else {
    // in TCP we find destination value in sock_common
    copy_skc_dest(&sk->__sk_common, &event->recv.destination);
  }

  output_network_event(ctx, event);
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

SEC("tracepoint/sys_exit_recvmsg")
int BPF_PROG(sys_exit_recvmsg, struct pt_regs *regs, int __syscall_nr,
             long ret) {
  do_recvmsg(ctx, ret);
  return 0;
}

SEC("tracepoint/sys_exit_recvmmsg")
int BPF_PROG(sys_exit_recvmmsg, struct pt_regs *regs, int __syscall_nr,
             long ret) {
  do_recvmsg(ctx, ret);
  return 0;
}

SEC("tracepoint/sys_enter_recvfrom")
int BPF_PROG(sys_enter_recvfrom, struct pt_regs *regs, int __syscall_nr, int fd,
             void *ubuf, size_t size, int flags, struct sockaddr *addr,
             int *addr_len, long ret) {
  save_recvmsg_addr(ctx, addr);
  return 0;
}

SEC("tracepoint/sys_exit_recvfrom")
int BPF_PROG(sys_exit_recvfrom, struct pt_regs *regs, int __syscall_nr,
             long ret) {
  do_recvmsg(ctx, ret);
  return 0;
}

SEC("tracepoint/sys_exit_read")
int BPF_PROG(sys_exit_read, struct pt_regs *regs, int __syscall_nr, long ret) {
  do_recvmsg(ctx, ret);
  return 0;
}

SEC("tracepoint/sys_exit_readv")
int BPF_PROG(sys_exit_readv, struct pt_regs *regs, int __syscall_nr, long ret) {
  do_recvmsg(ctx, ret);
  return 0;
}
