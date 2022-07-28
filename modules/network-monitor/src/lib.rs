use std::{
    fmt,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};

use bpf_common::{
    aya::include_bytes_aligned, parsing::DataArray, program::BpfContext, BpfSender, Pid, Program,
    ProgramBuilder, ProgramError,
};
use nix::sys::socket::{SockaddrIn, SockaddrIn6};

const MODULE_NAME: &str = "network-monitor";

pub async fn program(
    ctx: BpfContext,
    sender: impl BpfSender<NetworkEvent>,
) -> Result<Program, ProgramError> {
    let program = ProgramBuilder::new(
        ctx,
        MODULE_NAME,
        include_bytes_aligned!(concat!(env!("OUT_DIR"), "/probe.bpf.o")).into(),
    )
    .kprobe("__sys_bind")
    .kprobe("tcp_v4_connect")
    .kretprobe("tcp_v4_connect")
    .kprobe("tcp_v6_connect")
    .kretprobe("tcp_v6_connect")
    .kretprobe("inet_csk_accept")
    .kprobe("udp_sendmsg")
    .kprobe("udp_recvmsg")
    .kretprobe("udp_recvmsg")
    .kprobe("udpv6_sendmsg")
    .kprobe("udpv6_recvmsg")
    .kretprobe("udpv6_recvmsg")
    .kprobe("tcp_sendmsg")
    .kprobe("tcp_recvmsg")
    .kretprobe("tcp_recvmsg")
    .kprobe("tcp_set_state")
    .start()
    .await?;
    program.read_events("events", sender).await?;
    Ok(program)
}

const MAX_DATA_SIZE: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub enum NetworkEvent {
    Bind {
        addr: Addr,
    },
    Connect {
        src: Addr,
        dst: Addr,
    },
    Accept {
        src: Addr,
        dst: Addr,
    },
    // NOTE: source/destination here indicate the communication side rather
    // than the source of the message.
    Send {
        src: Addr,
        dst: Addr,
        data: DataArray<MAX_DATA_SIZE>,
        data_len: u32,
        proto: Proto,
    },
    Receive {
        src: Addr,
        dst: Addr,
        data: DataArray<MAX_DATA_SIZE>,
        data_len: u32,
        proto: Proto,
    },
    Close {
        original_pid: Pid,
        src: Addr,
        dst: Addr,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C, u8)]
pub enum Addr {
    V4(SockaddrIn),
    V6(SockaddrIn6),
}

impl From<Addr> for SocketAddr {
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
                SocketAddrV4::new(Ipv4Addr::from(octects), v.port()).into()
            }
            Addr::V6(v) => SocketAddr::new(v.ip().into(), v.port()),
        }
    }
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
            Addr::V4(v) => write!(f, "{}", v),
            Addr::V6(v) => write!(f, "{}", v),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Proto {
    TCP = 0,
    UDP = 1,
}

impl fmt::Display for NetworkEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkEvent::Bind { addr } => write!(f, "bind on {}", addr),
            NetworkEvent::Connect { src, dst } => {
                write!(f, "connect {} -> {}", src, dst)
            }
            NetworkEvent::Accept { src, dst } => {
                write!(f, "accept {} -> {}", src, dst)
            }
            NetworkEvent::Send { data_len, .. } => write!(f, "sent {} bytes", data_len),
            NetworkEvent::Receive { data_len, .. } => write!(f, "received {} bytes", data_len),
            NetworkEvent::Close {
                src,
                dst,
                original_pid,
            } => {
                write!(
                    f,
                    "close {} -> {} (original pid: {})",
                    src, dst, original_pid
                )
            }
        }
    }
}

pub mod pulsar {
    use super::*;
    use bpf_common::{program::BpfEvent, BpfSenderWrapper};
    use pulsar_core::{
        event::{DnsAnswer, DnsQuestion},
        pdk::{
            CleanExit, ModuleContext, ModuleError, Payload, PulsarModule, ShutdownSignal, Version,
        },
    };

    pub fn module() -> PulsarModule {
        PulsarModule::new(MODULE_NAME, Version::new(0, 0, 1), syscall_monitor_task)
    }

    async fn syscall_monitor_task(
        ctx: ModuleContext,
        mut shutdown: ShutdownSignal,
    ) -> Result<CleanExit, ModuleError> {
        let sender = ctx.get_sender();
        let dns_sender = ctx.get_sender();
        // intercept DNS
        let sender = BpfSenderWrapper::new(sender, move |event: &BpfEvent<NetworkEvent>| {
            if let Some(dns_event) = collect_dns_if_any(event) {
                dns_sender.send(event.pid, event.timestamp, dns_event);
            }
        });
        let _program = program(ctx.get_bpf_context(), sender).await?;
        shutdown.recv().await
    }

    impl From<NetworkEvent> for Payload {
        fn from(data: NetworkEvent) -> Self {
            match data {
                NetworkEvent::Bind { addr } => Payload::Bind {
                    address: addr.into(),
                },
                NetworkEvent::Connect { src, dst } => Payload::Connect {
                    source: src.into(),
                    destination: dst.into(),
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
                    is_tcp: matches!(proto, Proto::TCP),
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
                    is_tcp: matches!(proto, Proto::TCP),
                },
                NetworkEvent::Close {
                    src,
                    dst,
                    original_pid: _,
                } => Payload::Close {
                    source: src.into(),
                    destination: dst.into(),
                },
            }
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

        // any valid dns data?
        let dns = dns_parser::Packet::parse(data.as_ref()).ok()?;
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
}

#[cfg(feature = "test-suite")]
pub mod test_suite {
    use std::{
        io::{Read, Write},
        net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
        time::Duration,
    };

    use bpf_common::{
        event_check,
        parsing::DataArray,
        test_runner::{TestCase, TestReport, TestRunner},
    };
    use nix::{
        libc::kill,
        unistd::{fork, ForkResult},
    };
    use tokio::sync::{oneshot, watch};

    use super::*;

    pub fn tests() -> (&'static str, Vec<TestCase>) {
        (
            "network-monitor",
            vec![
                bind_ipv4(),
                bind_ipv6(),
                connect_ipv4(),
                connect_ipv6(),
                accept_ipv4(),
                accept_ipv6(),
                udp_ipv4_sendmsg_recvmsg(),
                udp_ipv6_sendmsg_recvmsg(),
                tcp_ipv4_sendmsg_recvmsg(),
                tcp_ipv6_sendmsg_recvmsg(),
                close_ipv4(),
                close_ipv6(),
            ],
        )
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
                let _listener = TcpListener::bind(&bind_addr).unwrap();
            })
            .expect_event(event_check!(
                NetworkEvent::Bind,
                (addr, bind_addr.into(), "address")
            ))
            .report()
            .await
    }

    fn connect_ipv4() -> TestCase {
        TestCase::new("connect_ipv4", run_connect_test("127.0.0.1:18020"))
    }

    fn connect_ipv6() -> TestCase {
        TestCase::new("connect_ipv6", run_connect_test("[::1]:18030"))
    }

    async fn run_connect_test(dest: &str) -> TestReport {
        let dest: SocketAddr = dest.parse().unwrap();
        let _listener = TcpListener::bind(&dest).unwrap();
        let (tx_source, rx_source) = oneshot::channel();
        TestRunner::with_ebpf(program)
            .run(|| {
                let stream = TcpStream::connect(dest).unwrap();
                let _ = tx_source.send(stream.local_addr().unwrap());
            })
            .expect_event(event_check!(
                NetworkEvent::Connect,
                (dst, dest.into(), "destination address"),
                (src, rx_source.await.unwrap().into(), "source address")
            ))
            .report()
            .await
    }

    fn accept_ipv4() -> TestCase {
        TestCase::new("accept_ipv4", run_accept_test("127.0.0.1:18040"))
    }

    fn accept_ipv6() -> TestCase {
        TestCase::new("accept_ipv6", run_accept_test("[::1]:18050"))
    }

    async fn run_accept_test(dest: &str) -> TestReport {
        let dest: SocketAddr = dest.parse().unwrap();
        let (tx_source, rx_source) = oneshot::channel();
        TestRunner::with_ebpf(program)
            .run(|| {
                let listener = TcpListener::bind(&dest).unwrap();
                let handle =
                    std::thread::spawn(move || TcpStream::connect(dest).unwrap().local_addr());
                listener.accept().unwrap();
                let _ = tx_source.send(handle.join().unwrap().unwrap());
            })
            .expect_event(event_check!(
                NetworkEvent::Accept,
                (src, rx_source.await.unwrap().into(), "source address"),
                (dst, dest.into(), "destination address")
            ))
            .report()
            .await
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
        let msg = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let data_copied = match proto {
            Proto::TCP => DataArray::from(&[][..]),
            Proto::UDP => DataArray::from(&msg[..]),
        };
        let (tx_source, rx_source) = watch::channel(None);
        TestRunner::with_ebpf(program)
            .run(|| match proto {
                Proto::UDP => {
                    let source = SocketAddr::new(dest.ip(), dest.port() + 1);
                    let _ = tx_source.send(Some(source));
                    let receiver = UdpSocket::bind(&dest).unwrap();
                    std::thread::spawn(move || {
                        let s = UdpSocket::bind(source).unwrap();
                        s.connect(dest).unwrap();
                        let _ = s.send(&msg).unwrap();
                    });
                    let mut buf = [0; 512];
                    assert_eq!(receiver.recv_from(&mut buf).unwrap(), (msg.len(), source));
                }
                Proto::TCP => {
                    let listener = TcpListener::bind(&dest).unwrap();
                    let t = std::thread::spawn(move || {
                        let mut client = TcpStream::connect(dest).unwrap();
                        client.write_all(&msg).unwrap();
                        client.local_addr().unwrap()
                    });
                    let mut connection = listener.accept().unwrap().0;
                    let mut buf = [0; 512];
                    assert_eq!(connection.read(&mut buf).unwrap(), msg.len());
                    let _ = tx_source.send(Some(t.join().unwrap()));
                }
            })
            .expect_event(event_check!(
                NetworkEvent::Send,
                (dst, dest.into(), "destination address"),
                (src, rx_source.borrow().unwrap().into(), "source address"),
                (data, data_copied.clone(), "data copy"),
                (data_len, msg.len() as u32, "real message len"),
                (proto, proto, "protocol")
            ))
            .expect_event(event_check!(
                NetworkEvent::Receive,
                (
                    dst,
                    rx_source.borrow().unwrap().into(),
                    "destination address"
                ),
                (src, dest.into(), "source address"),
                (data, data_copied.clone(), "data copy"),
                (data_len, msg.len() as u32, "real message len"),
                (proto, proto, "protocol")
            ))
            .report()
            .await
    }

    fn close_ipv4() -> TestCase {
        TestCase::new("close_ipv4", run_close_test("127.0.0.1:18110"))
    }

    fn close_ipv6() -> TestCase {
        TestCase::new("close_ipv6", run_close_test("[::1]:18110"))
    }

    async fn run_close_test(dest: &str) -> TestReport {
        let dest: SocketAddr = dest.parse().unwrap();
        let (tx_source, rx_source) = oneshot::channel();
        let (tx_pid, rx_pid) = oneshot::channel();
        // The on_tcp_set_state hook may be called by a process different from
        // the original creator the connection. This happens for example if it
        // receives a SIGKILL. We test this to make sure we're still emitting
        // an event with the correct origianl pid.
        TestRunner::with_ebpf(program)
            .run(|| {
                let dest = dest.clone();
                match unsafe { fork() }.unwrap() {
                    ForkResult::Child => {
                        let _conn = TcpStream::connect(dest).unwrap();
                        unreachable!();
                    }
                    ForkResult::Parent { child } => {
                        let _ = tx_pid.send(child);
                        let listener = TcpListener::bind(&dest).unwrap();
                        let (_connection, addr) = listener.accept().unwrap();
                        unsafe { kill(child.as_raw(), 9) };
                        let _ = tx_source.send(addr);
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            })
            // We use a custom check where we ignore the event pid since
            // it might be 0 or a ksoftirqd process.
            .expect_custom_event(
                None,
                true,
                event_check!(
                    NetworkEvent::Close,
                    (original_pid, rx_pid.await.unwrap().into(), "original pid"),
                    (src, rx_source.await.unwrap().into(), "source address"),
                    (dst, dest.into(), "dest address")
                ),
            )
            .report()
            .await
    }
}
