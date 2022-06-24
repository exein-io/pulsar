//! eBPF programs can use `bpf_printk` for simple logging, this module
//! forwards these debug events from tracefs to [`log::warn`]
//!
//! This module is disabled in release mode for performance reasons.

use std::os::unix::prelude::AsRawFd;

use bytes::BytesMut;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::oneshot;
use tokio_fd::AsyncFd;

const PATH: &str = "/sys/kernel/debug/tracing/trace_pipe";

pub struct StopHandle(oneshot::Sender<()>);

pub fn start() -> StopHandle {
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async {
        let file = match File::open(PATH).await {
            Ok(file) => file,
            Err(e) => {
                log::warn!("Error opening {}: {:?}", PATH, e);
                return;
            }
        };
        let mut file = match AsyncFd::try_from(file.as_raw_fd()) {
            Ok(file) => file,
            Err(e) => {
                log::warn!("Error opening {} as non-blocking: {:?}", PATH, e);
                return;
            }
        };
        log::info!("Logging events from {}", PATH);

        tokio::pin!(rx);
        loop {
            let mut buf = BytesMut::with_capacity(512);
            let file_event = tokio::select! {
                // wait for a new event
                f = file.read_buf(&mut buf) => f,
                // exit when stop handle is dropped
                _ = &mut rx => return,
            };
            if let Err(e) = file_event {
                log::warn!("Error reading from {}: {:?}", PATH, e);
                return;
            }
            buf[..]
                .split(|c| *c == b'\n')
                .filter(|bytes| !bytes.is_empty())
                .for_each(|bytes| log::warn!(target: "trace_pipe", "{}", format_msg(bytes)));
        }
    });

    StopHandle(tx)
}

/// Cleanup log messages from substrings we don't need
fn format_msg(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(msg) => msg.replace("bpf_trace_printk: ", ""),
        Err(_) => format!("{:?}", bytes),
    }
}
