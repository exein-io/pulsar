use std::{
    fmt,
    net::{Ipv4Addr, SocketAddr},
};

use bpf_common::{
    BpfSender, Pid, Program, ProgramBuilder, ProgramError, ebpf_program, parsing::BufferIndex,
    program::BpfContext,
};
use nix::sys::socket::{SockaddrIn, SockaddrIn6};
use pulsar_core::{
    event::{DnsAnswer, DnsQuestion},
    pdk::Payload,
};

const MODULE_NAME: &str = "network-monitor";

// This program intercepts network bind, connect, accept, send, receive and close events.
// If possible we use stable kernel hook points, like LSM or tracepoints. We fall back to
// kprobes if LSM is unavailable or a feature would not be possible.
//
// # Bind
// We find the address the server binds to in the `socket_bind` LSM hook.
// The `security_*` fallback kprobe is used.
//
// # Connect
// We find the address the client connects to in the `socket_connect` LSM hook.
//
// # Accept
// This one harder: the kernel calls the `socket_accept` hook the moment the server
// starts waiting for a connection, not when the connection really happens. This means
// that we can't find the source address when the hook is called.
// During `socket_accept` we'll save the `struct socket` pointer, but we'll read it
// only in the `sys_exit_accept`/`sys_exit_accept4` tracepoints, immediately before
// the kernel exits the syscall which caused the "accept" in the first place.
//
// # Send
// We read the address and content of sent messages using the `socket_sendmsg` LSM hook.
//
// # Receive
// We use the same strategy of "Accept": in `socket_recvmsg` we save in `args_map` the
// `struct socket` pointer and the `iov_base` pointer, which is the user-space location
// where the received data will be written.
// When exiting the syscall which caused the "recvmsg", we actually read the data and
// emit the event. Unfortunately there are many syscalls to intercept: recvmsg, recvmmsg,
// recvfrom, read, readv.
// Furthermore, for UDP connections, we also intercept `sys_enter_recvfrom`, where we save
// the `struct sockaddr` pointer. It will be used when exiting to read the source address.
//
// # Close
// We use the `tcp_set_state` kprobe to discover when a TCP connection is closed.
pub async fn program(
    ctx: BpfContext,
    sender: impl BpfSender<NetworkEvent>,
) -> Result<Program, ProgramError> {
    let attach_to_lsm = ctx.lsm_supported();
    let binary = ebpf_program!(&ctx, "probes");
    let mut builder = ProgramBuilder::new(ctx, MODULE_NAME, binary)
        .tracepoint("syscalls", "sys_exit_accept4")
        .tracepoint("syscalls", "sys_exit_accept")
        .kprobe("tcp_set_state")
        .cgroup_skb_egress("skb_egress")
        .cgroup_skb_ingress("skb_ingress");

    if attach_to_lsm {
        builder = builder
            .lsm("socket_bind")
            .lsm("socket_listen")
            .lsm("socket_connect")
            .lsm("socket_accept")
    } else {
        builder = builder
            .kprobe("security_socket_bind")
            .kprobe("security_socket_listen")
            .kprobe("security_socket_connect")
            .kprobe("security_socket_accept")
    }
    let mut program = builder.start().await?;
    program
        .read_events("map_output_network_event", sender)
        .await?;
    Ok(program)
}

#[derive(Debug)]
#[repr(C)]
pub enum NetworkEvent {
    Bind {
        addr: Addr,
        proto: Proto,
    },
    Listen {
        addr: Addr,
        // TCP-only
    },
    Connect {
        dst: Addr,
        proto: Proto,
    },
    Accept {
        src: Addr,
        dst: Addr,
        // TCP-only
    },
    // NOTE: source/destination here indicate the communication side rather
    // than the source of the message.
    Send {
        src: Addr,
        dst: Addr,
        data: BufferIndex<[u8]>,
        data_len: u32,
        proto: Proto,
    },
    Receive {
        src: Addr,
        dst: Addr,
        data: BufferIndex<[u8]>,
        data_len: u32,
        proto: Proto,
    },
    Close {
        original_pid: Pid,
        src: Addr,
        dst: Addr,
        // TCP-only
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C, u8)]
pub enum Addr {
    V4(SockaddrIn),
    V6(SockaddrIn6),
}

impl From<SocketAddr> for Addr {
    fn from(value: SocketAddr) -> Self {
        match value {
            SocketAddr::V4(v) => Addr::V4(v.into()),
            SocketAddr::V6(v) => Addr::V6(v.into()),
        }
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Addr::V4(v) => write!(f, "{v}"),
            Addr::V6(v) => write!(f, "{v}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Proto(u8);

impl Proto {
    pub const TCP: Self = Self(6);
    pub const UDP: Self = Self(17);

    pub fn is_tcp(&self) -> bool {
        self.0 == 6
    }
}

impl fmt::Display for NetworkEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkEvent::Bind { addr, proto } => write!(f, "bind on {addr} ({proto:?})"),
            NetworkEvent::Listen { addr } => write!(f, "listen on {addr}"),
            NetworkEvent::Connect { dst, proto } => write!(f, "connect -> {dst} ({proto:?})"),
            NetworkEvent::Accept { src, dst } => write!(f, "accept {src} -> {dst}"),
            NetworkEvent::Send { data_len, .. } => write!(f, "sent {data_len} bytes"),
            NetworkEvent::Receive { data_len, .. } => write!(f, "received {data_len} bytes"),
            NetworkEvent::Close {
                src,
                dst,
                original_pid,
            } => write!(f, "close {src} -> {dst} (original pid: {original_pid})"),
        }
    }
}

fn parse_dns(data: &[u8]) -> Option<Payload> {
    let dns = dns_parser::Packet::parse(data).ok()?;
    let with_q = !dns.questions.is_empty();
    let with_a = !dns.answers.is_empty();

    let mut questions = Vec::new();
    for q in dns.questions {
        questions.push(DnsQuestion {
            name: format!("{}", q.qname),
            qtype: format!("{:?}", q.qtype),
            qclass: format!("{:?}", q.qclass),
        });
    }

    let mut answers = Vec::new();
    for a in dns.answers {
        answers.push(DnsAnswer {
            name: format!("{}", a.name),
            class: format!("{:?}", a.cls),
            ttl: a.ttl,
            data: format!("{:?}", a.data),
        });
    }

    if with_q && !with_a {
        Some(Payload::DnsQuery { questions })
    } else if with_a {
        Some(Payload::DnsResponse { answers, questions })
    } else {
        None
    }
}

pub mod pulsar {
    use super::*;
    use bpf_common::{BpfSenderWrapper, parsing::IndexError, program::BpfEvent};
    use pulsar_core::{
        event::Host,
        pdk::{IntoPayload, ModuleContext, ModuleError, Payload, SimplePulsarModule},
    };

    pub struct NetworkMonitorModule;

    impl SimplePulsarModule for NetworkMonitorModule {
        type Config = pulsar_core::pdk::NoConfig;
        type State = NetworkMonitorState;

        const MODULE_NAME: &'static str = MODULE_NAME;
        const DEFAULT_ENABLED: bool = true;

        async fn init_state(
            &self,
            _config: &Self::Config,
            ctx: &ModuleContext,
        ) -> Result<Self::State, ModuleError> {
            let dns_ctx = ctx.clone();

            // intercept DNS
            let sender =
                BpfSenderWrapper::new(ctx.clone(), move |event: &BpfEvent<NetworkEvent>| {
                    if let Some(dns_event) = collect_dns_if_any(event) {
                        dns_ctx.send(event.pid, event.timestamp, dns_event);
                    }
                });

            Ok(Self::State {
                _ebpf_program: program(ctx.get_bpf_context(), sender).await?,
            })
        }
    }

    pub struct NetworkMonitorState {
        _ebpf_program: Program,
    }

    impl From<Addr> for Host {
        fn from(value: Addr) -> Self {
            match value {
                Addr::V4(v) => {
                    let bits = v.ip();
                    let octects = [
                        (bits >> 24) as u8,
                        (bits >> 16) as u8,
                        (bits >> 8) as u8,
                        bits as u8,
                    ];

                    Host {
                        ip: Ipv4Addr::from(octects).into(),
                        port: v.port(),
                    }
                }

                Addr::V6(v) => Host {
                    ip: v.ip().into(),
                    port: v.port(),
                },
            }
        }
    }

    impl IntoPayload for NetworkEvent {
        type Error = IndexError;

        fn try_into_payload(data: BpfEvent<Self>) -> Result<Payload, Self::Error> {
            Ok(match data.payload {
                NetworkEvent::Bind { addr, proto } => Payload::Bind {
                    address: addr.into(),
                    is_tcp: proto.is_tcp(),
                },
                NetworkEvent::Listen { addr } => Payload::Listen {
                    address: addr.into(),
                },
                NetworkEvent::Connect { dst, proto } => Payload::Connect {
                    destination: dst.into(),
                    is_tcp: proto.is_tcp(),
                },
                NetworkEvent::Accept { src, dst } => Payload::Accept {
                    source: src.into(),
                    destination: dst.into(),
                },
                NetworkEvent::Send {
                    src,
                    dst,
                    data_len,
                    proto,
                    ..
                } => Payload::Send {
                    source: src.into(),
                    destination: dst.into(),
                    len: data_len as usize,
                    is_tcp: proto.is_tcp(),
                },
                NetworkEvent::Receive {
                    src,
                    dst,
                    data_len,
                    proto,
                    ..
                } => Payload::Receive {
                    source: src.into(),
                    destination: dst.into(),
                    len: data_len as usize,
                    is_tcp: proto.is_tcp(),
                },
                NetworkEvent::Close {
                    src,
                    dst,
                    original_pid: _,
                } => Payload::Close {
                    source: src.into(),
                    destination: dst.into(),
                },
            })
        }
    }

    fn collect_dns_if_any(event: &BpfEvent<NetworkEvent>) -> Option<Payload> {
        let data = match &event.payload {
            NetworkEvent::Send { data, .. } => data,
            NetworkEvent::Receive { data, .. } => data,
            _ => return None,
        };

        if data.is_empty() {
            return None;
        }
        let data = data
            .bytes(&event.buffer)
            .map_err(|err| {
                log::error!("Error getting network packet payload: {err}");
            })
            .ok()?;

        // Check wheter the payload contains any DNS data.
        parse_dns(data)
    }
}

#[cfg(feature = "test-suite")]
pub mod test_suite {
    use std::{
        io::{Read, Write},
        net::{
            IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener,
            TcpStream, UdpSocket,
        },
        time::Duration,
    };

    use bpf_common::{
        event_check,
        test_runner::{TestCase, TestReport, TestRunner, TestSuite},
    };
    use dns_mock_server::Server;
    use hickory_resolver::{TokioAsyncResolver, config::*};
    use nix::{
        libc::kill,
        unistd::{ForkResult, fork},
    };
    use pulsar_core::pdk::Payload;

    use super::*;

    pub fn tests() -> TestSuite {
        TestSuite {
            name: "network-monitor",
            tests: vec![
                bind_ipv4(),
                bind_ipv6(),
                bind_udp(),
                connect_ipv4(),
                connect_ipv6(),
                connect_udp(),
                listen_ipv4(),
                listen_ipv6(),
                accept_ipv4(),
                accept_ipv6(),
                udp_ipv4_sendmsg_recvmsg(),
                udp_ipv6_sendmsg_recvmsg(),
                tcp_ipv4_sendmsg_recvmsg(),
                tcp_ipv6_sendmsg_recvmsg(),
                close_ipv4(),
                close_ipv6(),
                dns_ipv4(),
                dns_ipv6(),
            ],
        }
    }

    fn bind_ipv4() -> TestCase {
        TestCase::new("bind_ipv4", run_bind_test("127.0.0.1:18000"))
    }

    fn bind_ipv6() -> TestCase {
        TestCase::new("bind_ipv6", run_bind_test("[::1]:18010"))
    }

    async fn run_bind_test(bind_addr: &str) -> TestReport {
        let bind_addr: SocketAddr = bind_addr.parse().unwrap();
        TestRunner::with_ebpf(program)
            .run(|| {
                let _listener = TcpListener::bind(bind_addr).unwrap();
            })
            .await
            .expect_event(event_check!(
                NetworkEvent::Bind,
                (addr, bind_addr.into(), "address"),
                (proto, Proto::TCP, "protocol")
            ))
            .report()
    }

    fn bind_udp() -> TestCase {
        TestCase::new("bind_udp", async {
            let bind_addr: SocketAddr = "127.0.0.1:18001".parse().unwrap();
            TestRunner::with_ebpf(program)
                .run(|| {
                    let _listener = UdpSocket::bind(bind_addr).unwrap();
                })
                .await
                .expect_event(event_check!(
                    NetworkEvent::Bind,
                    (addr, bind_addr.into(), "address"),
                    (proto, Proto::UDP, "protocol")
                ))
                .report()
        })
    }

    fn connect_ipv4() -> TestCase {
        TestCase::new("connect_ipv4", run_connect_test("127.0.0.1:18020"))
    }

    fn connect_ipv6() -> TestCase {
        TestCase::new("connect_ipv6", run_connect_test("[::1]:18030"))
    }

    async fn run_connect_test(dest: &str) -> TestReport {
        let dest: SocketAddr = dest.parse().unwrap();
        let _listener = TcpListener::bind(dest).unwrap();
        TestRunner::with_ebpf(program)
            .run(|| {
                TcpStream::connect(dest).unwrap();
            })
            .await
            .expect_event(event_check!(
                NetworkEvent::Connect,
                (dst, dest.into(), "destination address"),
                (proto, Proto::TCP, "protocol")
            ))
            .report()
    }

    fn connect_udp() -> TestCase {
        TestCase::new("connect_udp", async {
            let bind_addr1: SocketAddr = "127.0.0.1:18021".parse().unwrap();
            let bind_addr2: SocketAddr = "127.0.0.1:18022".parse().unwrap();
            let _listener = UdpSocket::bind(bind_addr1).unwrap();
            TestRunner::with_ebpf(program)
                .run(|| {
                    UdpSocket::bind(bind_addr2)
                        .unwrap()
                        .connect(bind_addr1)
                        .unwrap();
                })
                .await
                .expect_event(event_check!(
                    NetworkEvent::Connect,
                    (dst, bind_addr1.into(), "address"),
                    (proto, Proto::UDP, "protocol")
                ))
                .report()
        })
    }

    fn listen_ipv4() -> TestCase {
        TestCase::new("listen_ipv4", run_listen_test("127.0.0.1:18035"))
    }

    fn listen_ipv6() -> TestCase {
        TestCase::new("listen_ipv6", run_listen_test("[::1]:18035"))
    }

    async fn run_listen_test(bind_addr: &str) -> TestReport {
        // This is identical to the bind test
        let bind_addr: SocketAddr = bind_addr.parse().unwrap();
        TestRunner::with_ebpf(program)
            .run(|| {
                let _listener = TcpListener::bind(bind_addr).unwrap();
            })
            .await
            .expect_event(event_check!(
                NetworkEvent::Listen,
                (addr, bind_addr.into(), "address")
            ))
            .report()
    }

    fn accept_ipv4() -> TestCase {
        TestCase::new("accept_ipv4", run_accept_test("127.0.0.1:18040"))
    }

    fn accept_ipv6() -> TestCase {
        TestCase::new("accept_ipv6", run_accept_test("[::1]:18050"))
    }

    async fn run_accept_test(dest: &str) -> TestReport {
        let dest: SocketAddr = dest.parse().unwrap();
        let mut source = dest;
        TestRunner::with_ebpf(program)
            .run(|| {
                let listener = TcpListener::bind(dest).unwrap();
                let handle =
                    std::thread::spawn(move || TcpStream::connect(dest).unwrap().local_addr());
                listener.accept().unwrap();
                source = handle.join().unwrap().unwrap();
            })
            .await
            .expect_event(event_check!(
                NetworkEvent::Accept,
                (src, source.into(), "source address"),
                (dst, dest.into(), "destination address")
            ))
            .report()
    }

    fn udp_ipv4_sendmsg_recvmsg() -> TestCase {
        TestCase::new(
            "udp_ipv4_sendmsg_recvmsg",
            run_msg_test("127.0.0.1:18060", Proto::UDP),
        )
    }

    fn udp_ipv6_sendmsg_recvmsg() -> TestCase {
        TestCase::new(
            "udp_ipv6_sendmsg_recvmsg",
            run_msg_test("[::1]:18070", Proto::UDP),
        )
    }

    fn tcp_ipv4_sendmsg_recvmsg() -> TestCase {
        TestCase::new(
            "tcp_ipv4_sendmsg_recvmsg",
            run_msg_test("127.0.0.1:18080", Proto::TCP),
        )
    }

    fn tcp_ipv6_sendmsg_recvmsg() -> TestCase {
        TestCase::new(
            "tcp_ipv6_sendmsg_recvmsg",
            run_msg_test("[::1]:18090", Proto::TCP),
        )
    }

    // Spawn a server listening for messages and a client which sends a predefined
    // msg to it. Make sure we've observing both the sendmsg and recvmsg events.
    async fn run_msg_test(dest: &str, proto: Proto) -> TestReport {
        let dest: SocketAddr = dest.parse().unwrap();
        // for UDP, we use the next port as the source
        // for TCP it's overriden on connection
        let mut source = dest;
        let msg = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        TestRunner::with_ebpf(program)
            .run(|| match proto {
                Proto::UDP => {
                    source.set_port(dest.port() + 1);
                    let receiver = UdpSocket::bind(dest).unwrap();
                    std::thread::spawn(move || {
                        let s = UdpSocket::bind(source).unwrap();
                        s.connect(dest).unwrap();
                        s.send(&msg).unwrap();
                    });
                    let mut buf = [0; 512];
                    assert_eq!(receiver.recv_from(&mut buf).unwrap(), (msg.len(), source));
                }
                Proto::TCP => {
                    let listener = TcpListener::bind(dest).unwrap();
                    let t = std::thread::spawn(move || {
                        let mut client = TcpStream::connect(dest).unwrap();
                        client.write_all(&msg).unwrap();
                        client.local_addr().unwrap()
                    });
                    let mut connection = listener.accept().unwrap().0;
                    let mut buf = [0; 512];
                    assert_eq!(connection.read(&mut buf).unwrap(), msg.len());
                    source = t.join().unwrap();
                }
                _ => {
                    // skip
                }
            })
            .await
            .expect_event(event_check!(
                NetworkEvent::Send,
                (dst, dest.into(), "destination address"),
                (src, source.into(), "source address"),
                (data, msg.to_vec(), "data copy"),
                (data_len, msg.len() as u32, "real message len"),
                (proto, proto, "protocol")
            ))
            .expect_event(event_check!(
                NetworkEvent::Receive,
                (dst, source.into(), "destination address"),
                (src, dest.into(), "source address"),
                (data, msg.to_vec(), "data copy"),
                (data_len, msg.len() as u32, "real message len"),
                (proto, proto, "protocol")
            ))
            .report()
    }

    fn close_ipv4() -> TestCase {
        TestCase::new("close_ipv4", run_close_test("127.0.0.1:18110"))
    }

    fn close_ipv6() -> TestCase {
        TestCase::new("close_ipv6", run_close_test("[::1]:18110"))
    }

    async fn run_close_test(dest: &str) -> TestReport {
        let dest: SocketAddr = dest.parse().unwrap();
        let mut source = dest;
        let mut expected_pid = Pid::from_raw(0);
        let listener = TcpListener::bind(dest).unwrap();
        // The on_tcp_set_state hook may be called by a process different from
        // the original creator the connection. This happens for example if it
        // receives a SIGKILL. We test this to make sure we're still emitting
        // an event with the correct origianl pid.
        TestRunner::with_ebpf(program)
            .run(|| match unsafe { fork() }.unwrap() {
                ForkResult::Child => {
                    let _conn = TcpStream::connect(dest).unwrap();
                }
                ForkResult::Parent { child } => {
                    expected_pid = child;
                    let (_connection, addr) = listener.accept().unwrap();
                    unsafe { kill(child.as_raw(), 9) };
                    source = addr;
                    std::thread::sleep(Duration::from_millis(100));
                }
            })
            // We use a custom check where we ignore the event pid since
            // it might be 0 or a ksoftirqd process.
            .await
            .expect_custom_event(
                None,
                true,
                event_check!(
                    NetworkEvent::Close,
                    (original_pid, expected_pid, "original pid"),
                    (src, source.into(), "source address"),
                    (dst, dest.into(), "dest address")
                ),
            )
            .report()
    }

    fn dns_ipv4() -> TestCase {
        TestCase::new(
            "dns_ipv4",
            run_dns(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18110)),
                "example.io".to_string(),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "A".to_string(),
            ),
        )
    }

    fn dns_ipv6() -> TestCase {
        TestCase::new(
            "dns_ipv6",
            run_dns(
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 18110, 0, 0)),
                "example.io".to_string(),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                "AAAA".to_string(),
            ),
        )
    }

    async fn run_dns(
        addr: SocketAddr,
        domain: String,
        address: IpAddr,
        expected_record_type: String,
    ) -> TestReport {
        // Create necessary copies for each non-terminal closure.
        let dns_server_domain = domain.clone();
        let dns_query_domain = domain.clone();
        TestRunner::with_ebpf(program)
            .run_async(async move {
                // DNS server.
                let mut server = Server::default();
                server
                    .add_records(&dns_server_domain, vec![address])
                    .unwrap();
                let socket = tokio::net::UdpSocket::bind(&addr).await.unwrap();
                let local_addr = socket.local_addr().unwrap();
                tokio::spawn(async move {
                    server.start(socket).await.unwrap();
                });

                // DNS requests.
                let mut config = ResolverConfig::new();
                config.add_name_server(NameServerConfig::new(local_addr, Protocol::Udp));
                let resolver = TokioAsyncResolver::tokio(config, ResolverOpts::default());
                resolver.lookup_ip(&dns_server_domain).await.unwrap();
            })
            .await
            .expect(move |event| {
                if let NetworkEvent::Send { data, .. } = &event.payload {
                    if data.is_empty() {
                        return false;
                    }
                    let data = data.bytes(&event.buffer).unwrap();
                    match parse_dns(data) {
                        Some(Payload::DnsQuery { questions }) => {
                            questions.iter().any(|q| q.name == dns_query_domain)
                        }
                        _ => false,
                    }
                } else {
                    false
                }
            })
            .expect(move |event| {
                if let NetworkEvent::Receive { data, .. } = &event.payload {
                    if data.is_empty() {
                        return false;
                    }
                    let data = data.bytes(&event.buffer).unwrap();
                    match parse_dns(data) {
                        Some(Payload::DnsResponse { questions, answers }) => {
                            let expected_record =
                                format!("{expected_record_type}(Record({address}))");
                            questions.iter().any(|q| q.name == domain)
                                && answers
                                    .iter()
                                    .any(|a| a.name == domain && a.data == expected_record)
                        }
                        _ => false,
                    }
                } else {
                    false
                }
            })
            .report()
    }
}
