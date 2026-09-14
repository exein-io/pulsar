//! Regression tests for the `process_skb` error paths (issue #381).
//!
//! Normal traffic never reaches those paths, so the leak check in `TestRunner`
//! watches code nobody walks. Each test here walks one of them: it sends a
//! burst of malformed packets through a raw `IP_HDRINCL` socket, then one well
//! formed packet, and asserts the well formed one is reported.
//!
//! That single assertion does two jobs. It is the control proving raw packets
//! reach the eBPF program at all, and it fails if a slot leaked, because the
//! burst exhausts the three nesting slots and `init_network_event` then refuses
//! every later event. `TestRunner` adds its own leak assertion on top, which
//! catches a single leaked slot rather than only saturation.
//!
//! Everything is sent from one pinned cpu: the nesting counter is per-cpu, so
//! leaks spread over cpus never saturate.
//!
//! Which branches are reachable is decided by `raw_send_hdrinc()`, which
//! refuses packets below 20 bytes and any `ihl * 4` larger than the packet, and
//! overwrites `tot_len`. That leaves the four cases below, all of them a valid
//! IPv4 header over a truncated L4 one, which no kernel inspects. Not covered:
//!
//! - packets too short for their IP header: the kernel enforces a minimum.
//! - an invalid `ihl`: whether such a packet ever reaches the program depends
//!   on the kernel and on the environment's netfilter rules. The same 6.6
//!   kernel accepts it under architest and rejects it with EPERM under lvh, and
//!   a 7.1 host rejects it with EINVAL, so a test for it passes, fails or is
//!   inert depending on where it runs.
//! - unsupported L3 protocols: the hook only ever sees IPv4/IPv6.
//! - `headers_len > skb->len`: dead, the preceding checks already bound it.
//!
//! Every sendto must succeed; a refused one means the test stopped testing
//! anything and is reported as a failure rather than skipped.
//!
//! These tests only mean something if they fail without the fix. When changing
//! them, check them against a build with the decrement in `discard_##struct_name`
//! (`output.bpf.h`) commented out: all four must fail.

use std::{
    io, mem,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use bpf_common::{
    event_check,
    test_runner::{TestCase, TestReport, TestRunner},
};
use nix::libc;

use crate::{NetworkEvent, Proto, program};

/// Exhausts MAX_PREEMPTION_NESTING_LEVEL (3) if every packet leaks its slot.
const BURST: usize = 8;

pub(super) fn tests() -> Vec<TestCase> {
    vec![
        TestCase::new(
            "malformed_icmp_header",
            run(ipv4(5, libc::IPPROTO_ICMP as u8, &[0; 4]), 18210),
        ),
        TestCase::new(
            "malformed_tcp_header",
            run(ipv4(5, libc::IPPROTO_TCP as u8, &[0; 4]), 18220),
        ),
        TestCase::new(
            "malformed_tcp_data_offset",
            run(ipv4(5, libc::IPPROTO_TCP as u8, &tcp_header(0)), 18230),
        ),
        TestCase::new(
            "malformed_udp_header",
            run(ipv4(5, libc::IPPROTO_UDP as u8, &[0; 4]), 18240),
        ),
    ]
}

async fn run(malformed: Vec<u8>, port: u16) -> TestReport {
    let payload = [0xaa; 16];
    let source: SocketAddr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into();
    let dest: SocketAddr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port + 1).into();
    let control = udp(port, port + 1, &payload);

    TestRunner::with_ebpf(program)
        .run(move || {
            on_cpu0(move || {
                let fd = raw_socket();
                for _ in 0..BURST {
                    send(&fd, &malformed).expect("sending a malformed packet");
                }
                // Must always go out: this is the assertion the test rests on.
                send(&fd, &control).expect("sending the control packet");
            })
        })
        .await
        .expect_event(event_check!(
            NetworkEvent::Send,
            (src, source.into(), "source address"),
            (dst, dest.into(), "destination address"),
            (data, payload.to_vec(), "data copy"),
            (data_len, payload.len() as u32, "payload len"),
            (proto, Proto::UDP, "protocol")
        ))
        .report()
}

/// IPv4 header with the given `ihl` and `proto`, followed by `payload`. The
/// kernel fills in tot_len and the checksum.
fn ipv4(ihl: u8, proto: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 20];
    packet[0] = (4 << 4) | ihl;
    packet[8] = 64; // ttl
    packet[9] = proto;
    packet[12..16].copy_from_slice(&Ipv4Addr::LOCALHOST.octets());
    packet[16..20].copy_from_slice(&Ipv4Addr::LOCALHOST.octets());
    packet.extend_from_slice(payload);
    packet
}

/// TCP header with the given data offset, in 32 bit words.
fn tcp_header(doff: u8) -> [u8; 20] {
    let mut header = [0u8; 20];
    header[12] = doff << 4;
    header
}

/// Well formed datagram: the packet every test expects back as an event.
fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut datagram = Vec::with_capacity(8 + payload.len());
    datagram.extend_from_slice(&sport.to_be_bytes());
    datagram.extend_from_slice(&dport.to_be_bytes());
    datagram.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    datagram.extend_from_slice(&[0, 0]); // checksum is optional over IPv4
    datagram.extend_from_slice(payload);
    ipv4(5, libc::IPPROTO_UDP as u8, &datagram)
}

/// Returns an `OwnedFd` so the socket is closed on drop, at the end of the
/// sending closure.
fn raw_socket() -> OwnedFd {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    assert!(fd >= 0, "raw socket: {}", io::Error::last_os_error());
    // SAFETY: socket() returned a fresh descriptor.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

fn send(fd: &OwnedFd, packet: &[u8]) -> io::Result<()> {
    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_addr.s_addr = u32::from_ne_bytes(Ipv4Addr::LOCALHOST.octets());
    let sent = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            packet.as_ptr().cast(),
            packet.len(),
            0,
            std::ptr::addr_of!(addr).cast(),
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Run `f` on a thread pinned to cpu 0 and wait for it. A dedicated thread
/// keeps the affinity off the tokio worker running the test.
fn on_cpu0(f: impl FnOnce() + Send + 'static) {
    std::thread::spawn(move || {
        let mut cpus = unsafe { mem::zeroed::<libc::cpu_set_t>() };
        unsafe { libc::CPU_SET(0, &mut cpus) };
        let ret = unsafe { libc::sched_setaffinity(0, mem::size_of::<libc::cpu_set_t>(), &cpus) };
        assert_eq!(ret, 0, "sched_setaffinity: {}", io::Error::last_os_error());
        f()
    })
    .join()
    .unwrap();
}
