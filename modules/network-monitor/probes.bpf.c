// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "common.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ADDR_SIZE 16
#define EVENT_BIND 0
#define EVENT_CONNECT 1
#define EVENT_ACCEPT 2
#define EVENT_SEND 3
#define EVENT_RECV 4
#define EVENT_CLOSE 5

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
};

struct connect_event {
  struct address source;
  struct address destination;
};

struct accept_event {
  struct address source;
  struct address destination;
};

struct msg_event {
  struct address source;
  struct address destination;
  u32 copied_data_len;
  u8 data[MAX_DATA_SIZE];
  u32 data_len;
  u8 proto;
};

struct close_event {
  pid_t original_pid;
  struct address source;
  struct address destination;
};

struct network_event {
  u64 timestamp;
  pid_t pid;
  u32 event_type;
  union {
    struct bind_event bind;
    struct connect_event connect;
    struct accept_event accept;
    struct msg_event send;
    struct msg_event recv;
    struct close_event close;
  };
};

// used to send events to userspace
struct bpf_map_def SEC("maps/events") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 0,
};

// save input argument to
struct bpf_map_def SEC("maps/sk") skmap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct sock *),
    .max_entries = 10240,
};

// The BPF stack limit of 512 bytes is exceeded by network_event, so we use
// a per-cpu array as a workaround
struct bpf_map_def SEC("maps/event") eventmem = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct network_event),
    .max_entries = 1,
};

// Map a socket pointer to its creating process
struct bpf_map_def SEC("maps/tcp_set_state") tcp_set_state_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct sock *),
    .value_size = sizeof(pid_t),
    .max_entries = 10240,
};

struct recvmsg_args {
  struct sock *sk;
  struct msghdr *msg;
};

struct bpf_map_def SEC("maps/recvmsgmap") recvmsgmap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct recvmsg_args),
    .max_entries = 10240,
};

const int IPV6_NUM_OCTECTS = 16;
const int IPV4_NUM_OCTECTS = 4;

static __always_inline struct network_event *new_event() {
  u32 key = 0;
  struct network_event *event = bpf_map_lookup_elem(&eventmem, &key);
  if (!event) {
    bpf_printk("can't get event memory");
    return 0;
  }
  int i;
  for (i = 0; i < 100; i++) {
    *(((u8 *)event) + i) = 0;
  }
  return event;
}

// Copy an address from a sockaddr
static __always_inline void copy_sockaddr(struct sockaddr *addr,
                                          struct address *dest,
                                          bool is_user_memory) {
  long (*read)(void *, __u32, const void *) = NULL;
  if (is_user_memory)
    read = bpf_probe_read_user;
  else
    read = bpf_probe_read_kernel;

  u16 family = 0;
  read(&family, sizeof(family), &addr->sa_family);
  switch (family) {
  case AF_INET: {
    dest->ip_ver = 0;
    read(&dest->v4, sizeof(struct sockaddr_in), addr);
    break;
  }
  case AF_INET6: {
    dest->ip_ver = 1;
    read(&dest->v6, sizeof(struct sockaddr_in6), addr);
    break;
  }
  default:
    bpf_printk("ignored sockaddr famility %d", family);
  }
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
    break;
  }
  case AF_INET6: {
    addr->ip_ver = 1;
    addr->v6.sin6_port = port;
    bpf_core_read(&addr->v6.sin6_addr, IPV6_NUM_OCTECTS,
                  &sk->skc_v6_rcv_saddr.in6_u.u6_addr32);
    break;
  }
  default:
    bpf_printk("ignored sockaddr famility %d", family);
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
    break;
  }
  case AF_INET6: {
    addr->ip_ver = 1;
    bpf_core_read(&addr->v6.sin6_port, sizeof(u16), &sk->skc_dport);
    bpf_core_read(&addr->v6.sin6_addr, IPV6_NUM_OCTECTS,
                  &sk->skc_v6_daddr.in6_u.u6_addr32);
    break;
  }
  default:
    bpf_printk("ignored sockaddr famility %d", family);
  }
}

SEC("kprobe/__sys_bind")
int __sys_bind(struct pt_regs *ctx) {
  pid_t tgid = interesting_tgid();
  if (tgid < 0)
    return 0;

  int fd = PT_REGS_PARM1(ctx);
  struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2(ctx);
  struct network_event *event = new_event();
  if (!event)
    return 0;
  event->event_type = EVENT_BIND;
  event->pid = tgid;
  event->timestamp = bpf_ktime_get_ns();
  copy_sockaddr(addr, &event->bind.addr, true);

  int r = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                                sizeof(struct network_event));
  return 0;
}

static __always_inline int do_connect(struct pt_regs *ctx) {
  pid_t tgid = interesting_tgid();
  if (tgid < 0)
    return 0;

  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  u64 pid_tgid = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&skmap, &pid_tgid, &sk, BPF_ANY);

  return 0;
}

static __always_inline int do_connect_return(struct pt_regs *ctx) {
  pid_t tgid = interesting_tgid();
  if (tgid < 0)
    return 0;

  struct sock **skpp, *sk;
  u64 pid_tgid = bpf_get_current_pid_tgid();
  skpp = bpf_map_lookup_elem(&skmap, &pid_tgid);
  if (skpp == 0) {
    bpf_printk("missed entry in skmap");
    return 0;
  }

  // if ret!=0, connect failed to send SYNC packet, and sk may not have
  // populated
  int ret = PT_REGS_RC(ctx);
  if (ret == 0) {
    struct network_event *event = new_event();
    if (!event)
      return 0;
    event->event_type = EVENT_CONNECT;
    event->pid = tgid;
    event->timestamp = bpf_ktime_get_ns();

    sk = *skpp;

    copy_skc_source(&sk->__sk_common, &event->connect.source);
    copy_skc_dest(&sk->__sk_common, &event->connect.destination);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                          sizeof(struct network_event));
  } else {
    bpf_printk("failed connect");
  }

  bpf_map_delete_elem(&skmap, &pid_tgid);

  return 0;
}

SEC("kprobe/tcp_v4_connect")
int tcp_v4_connect(struct pt_regs *ctx) { return do_connect(ctx); }

SEC("kprobe/tcp_v6_connect")
int tcp_v6_connect(struct pt_regs *ctx) { return do_connect(ctx); }

SEC("kretprobe/tcp_v4_connect_return")
int tcp_v4_connect_return(struct pt_regs *ctx) {
  return do_connect_return(ctx);
}

SEC("kretprobe/tcp_v6_connect_return")
int tcp_v6_connect_return(struct pt_regs *ctx) {
  return do_connect_return(ctx);
}

SEC("kretprobe/inet_csk_accept_return")
int inet_csk_accept_return(struct pt_regs *ctx) {
  pid_t tgid = interesting_tgid();
  if (tgid < 0)
    return 0;

  struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
  if (!sk) {
    bpf_printk("accept returned null");
    return 0;
  }

  struct network_event *event = new_event();
  if (!event)
    return 0;
  event->event_type = EVENT_ACCEPT;
  event->pid = tgid;
  event->timestamp = bpf_ktime_get_ns();

  copy_skc_source(&sk->__sk_common, &event->accept.destination);
  copy_skc_dest(&sk->__sk_common, &event->accept.source);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct network_event));
  return 0;
}

static __always_inline void read_iovec(struct msg_event *event,
                                       struct msghdr *msg) {
  size_t len = event->data_len;
  event->copied_data_len = 0;

  unsigned int msg_iter_type = 0;

  struct iovec *iov = NULL;
  bpf_core_read(&iov, sizeof(iov), &msg->msg_iter.iov);

  if (len > MAX_DATA_SIZE) {
    bpf_printk("len=%d MAX_DATA_SIZE=%d", len, MAX_DATA_SIZE);
  }

  void *iovbase = NULL;
  bpf_core_read(&iovbase, sizeof(iovbase), &iov->iov_base);

  // limit the index to avoid "min value is negative, either use unsigned or
  // 'var &= const'"
  len &= (MAX_DATA_SIZE - 1);

  int r = bpf_core_read_user(event->data, len, iovbase);
  if (r) {
    bpf_printk("cant read data %d", r);
  }
  event->copied_data_len = len;
  // bpf_printk("get data size %d -> %d", len, len & (MAX_DATA_SIZE - 1));
}

static __always_inline int do_sendmsg(struct pt_regs *regs, u8 proto) {
  pid_t tgid = interesting_tgid();
  if (tgid < 0)
    return 0;

  struct sock *sk = (struct sock *)PT_REGS_PARM1(regs);
  struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(regs);

  struct network_event *event = new_event();
  if (!event) {
    bpf_printk("can't get event memory");
    return 0;
  }
  event->event_type = EVENT_SEND;
  event->pid = tgid;
  event->timestamp = bpf_ktime_get_ns();
  event->send.proto = proto;

  size_t len = (size_t)PT_REGS_PARM3(regs);
  if (len <= 0)
    return 0;
  event->send.data_len = len;
  // Copy data only for UDP events since we want to intercept DNS requests
  if (proto == PROTO_UDP) {
    read_iovec(&event->send, msg);
  }

  copy_skc_source(&sk->__sk_common, &event->send.source);
  copy_skc_dest(&sk->__sk_common, &event->send.destination);

  bpf_perf_event_output(regs, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct network_event));

  return 0;
}

static __always_inline int save_recvmsg(struct pt_regs *regs) {
  pid_t tgid = interesting_tgid();
  if (tgid < 0)
    return 0;
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct recvmsg_args args = {
      .sk = (struct sock *)PT_REGS_PARM1(regs),
      .msg = (struct msghdr *)PT_REGS_PARM2(regs),
  };
  int r = bpf_map_update_elem(&recvmsgmap, &pid_tgid, &args, BPF_NOEXIST);
  if (r) {
    bpf_printk("INSERT ERROR on recvmsgmap: %d %d", pid_tgid, r);
  } else {
    // bpf_printk("insert recvmsgmap: %d %d", pid_tgid, r);
  }
  return 0;
}

static __always_inline int do_recvmsg(struct pt_regs *regs, u8 proto) {
  pid_t tgid = interesting_tgid();
  if (tgid < 0)
    return 0;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct recvmsg_args *args = bpf_map_lookup_elem(&recvmsgmap, &pid_tgid);
  int r = bpf_map_delete_elem(&recvmsgmap, &pid_tgid);
  // bpf_printk("remove recvmsgmap: %d %d", pid_tgid, r);
  if (!args) {
    return 0;
  }
  struct sock *sk = args->sk;
  struct msghdr *msg = args->msg;

  struct network_event *event = new_event();
  if (!event) {
    bpf_printk("can't get event memory");
    return 0;
  }
  event->event_type = EVENT_RECV;
  event->pid = tgid;
  event->timestamp = bpf_ktime_get_ns();
  event->recv.proto = proto;

  int len = PT_REGS_RC(regs);
  if (len <= 0)
    return 0;
  event->recv.data_len = len;
  // Copy data only for UDP events since we want to intercept DNS replies
  if (proto == PROTO_UDP) {
    read_iovec(&event->recv, msg);
  }

  u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

  copy_skc_source(&sk->__sk_common, &event->connect.source);
  if (proto == PROTO_UDP) {
    // in UDP we find destination value in sockaddr
    // NOTE: msg_name is NULL if the userspace code is not interested
    // in knowing the source of the message. In that case we won't extract
    // the source port and address.
    struct sockaddr *msg_name = 0;
    int k = bpf_core_read(&msg_name, sizeof(msg_name), &msg->msg_name);
    if (!msg_name) {
      bpf_printk("msg_name is null. %d", k);
    } else {
      copy_sockaddr(msg_name, &event->connect.destination, false);
    }
  } else {
    // in TCP we find destination value in sock_common
    copy_skc_dest(&sk->__sk_common, &event->connect.destination);
  }

  bpf_perf_event_output(regs, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct network_event));
  return 0;
}

SEC("kprobe/udp_sendmsg")
int udp_sendmsg(struct pt_regs *ctx) { return do_sendmsg(ctx, PROTO_UDP); }

SEC("kprobe/udpv6_sendmsg")
int udpv6_sendmsg(struct pt_regs *ctx) { return do_sendmsg(ctx, PROTO_UDP); }

SEC("kprobe/tcp_sendmsg")
int tcp_sendmsg(struct pt_regs *ctx) { return do_sendmsg(ctx, PROTO_TCP); }

SEC("kprobe/udp_recvmsg")
int udp_recvmsg(struct pt_regs *ctx) { return save_recvmsg(ctx); }

SEC("kprobe/udpv6_recvmsg")
int udpv6_recvmsg(struct pt_regs *ctx) { return save_recvmsg(ctx); }

SEC("kretprobe/udp_recvmsg_return")
int udp_recvmsg_return(struct pt_regs *ctx) {
  return do_recvmsg(ctx, PROTO_UDP);
}

SEC("kretprobe/udpv6_recvmsg_return")
int udpv6_recvmsg_return(struct pt_regs *ctx) {
  return do_recvmsg(ctx, PROTO_UDP);
}

SEC("kprobe/tcp_recvmsg")
int tcp_recvmsg(struct pt_regs *regs) { return save_recvmsg(regs); }

SEC("kretprobe/tcp_recvmsg_return")
int tcp_recvmsg_return(struct pt_regs *regs) {
  return do_recvmsg(regs, PROTO_TCP);
}

SEC("kprobe/tcp_set_state")
int tcp_set_state(struct pt_regs *regs) {
  pid_t tgid = interesting_tgid();
  if (tgid < 0)
    return 0;

  int ret;
  struct sock *sk = (struct sock *)PT_REGS_PARM1(regs);
  int state = (int)PT_REGS_PARM2(regs);
  if (state == TCP_SYN_SENT || state == TCP_LAST_ACK) {
    bpf_printk("OPEN %d", sk);
    ret = bpf_map_update_elem(&tcp_set_state_map, &sk, &tgid, BPF_ANY);
    if (ret) {
      bpf_printk("(tcp_set_state) ERROR updating p_set_state_map");
    }
    return 0;
  }
  if (state != TCP_CLOSE)
    return 0;
  pid_t *id = bpf_map_lookup_elem(&tcp_set_state_map, &sk);
  pid_t original_pid = tgid;
  if (!id) {
    bpf_printk("(tcp_set_state) ERROR retrieving original pid");
    return 0;
  } else {
    original_pid = *id;
  }
  ret = bpf_map_delete_elem(&tcp_set_state_map, &sk);
  if (ret) {
    bpf_printk("(tcp_set_state) ERROR deleting element from p_set_state_map");
  }

  u16 family = 0;
  bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family);
  short ipver = family == AF_INET ? 4 : 6;
  u32 key = 0;

  struct network_event *event = new_event();
  if (!event)
    return 0;
  event->event_type = EVENT_CLOSE;
  event->pid = tgid;
  event->close.original_pid = original_pid;
  event->timestamp = bpf_ktime_get_ns();
  copy_skc_source(&sk->__sk_common, &event->close.source);
  copy_skc_dest(&sk->__sk_common, &event->close.destination);

  ret = bpf_perf_event_output(regs, &events, BPF_F_CURRENT_CPU, event,
                              sizeof(struct network_event));
  if (ret) {
    bpf_printk("(tcp_set_state) ERROR on perf event output");
  }
  return 0;
}
