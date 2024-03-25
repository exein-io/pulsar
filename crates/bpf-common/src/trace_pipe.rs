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

#[allow(unused)]
pub struct StopHandle(oneshot::Sender<()>);

pub async fn start() -> StopHandle {
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        if let Some((mut async_fd, _open_file)) = open_trace_pipe().await {
            log::info!("Logging events from {}", PATH);

            tokio::pin!(rx);
            let mut buf = BytesMut::with_capacity(512);
            loop {
                let file_event = tokio::select! {
                    // wait for a new event
                    f = async_fd.read_buf(&mut buf) => f,
                    // exit when stop handle is dropped
                    _ = &mut rx => return,
                };
                if let Err(e) = file_event {
                    log::warn!("Error reading from {}: {:?}", PATH, e);
                    return;
                }
                if let Some(last_newline) = buf[..].iter().rposition(|&x| x == b'\n') {
                    let completed_lines = buf.split_to(last_newline);
                    print_buffer(&completed_lines[..]);
                }
            }
        }
    });

    StopHandle(tx)
}

/// Open the trace pipe file and returns:
/// - An AsyncFd which can be used to read asynchronously from it.
///   NOTE: we can't just use tokio::fs::File because it uses blocking IO on
///   a different thread. If we do, Ctrl-C won't quit the application since
///   we're still stuck reading this file.
/// - The original tokio::fs::File is returned and must not be dropped until
///   we're done reading from the async fd. Dropping it would close the FD,
///   resulting in EBADFD errors when trying to read.
async fn open_trace_pipe() -> Option<(AsyncFd, File)> {
    let file = match File::open(PATH).await {
        Ok(file) => file,
        Err(e) => {
            log::warn!("Error opening {}: {:?}", PATH, e);
            return None;
        }
    };
    let async_fd = match AsyncFd::try_from(file.as_raw_fd()) {
        Ok(async_fd) => async_fd,
        Err(e) => {
            log::warn!("Error opening {} as non-blocking: {:?}", PATH, e);
            return None;
        }
    };
    Some((async_fd, file))
}

fn print_buffer(buf: &[u8]) {
    buf.split(|c| *c == b'\n')
        .filter(|bytes| !bytes.is_empty())
        .for_each(|bytes| log::warn!(target: "trace_pipe", "{}", format_msg(bytes)));
}

/// Cleanup log messages from substrings we don't need
fn format_msg(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(msg) => msg.replace("bpf_trace_printk: ", ""),
        Err(_) => format!("{bytes:?}"),
    }
}
