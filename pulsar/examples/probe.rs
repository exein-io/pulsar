use std::future::Future;

use bpf_common::{
    program::{BpfContext, Pinning},
    Program, ProgramError,
};
use clap::Parser;
use tokio::sync::mpsc;

/// Test runner for eBPF programs
#[derive(Parser, Debug)]
#[clap(name = "probe")]
#[clap(author, version, about, long_about = None)]
enum Probe {
    #[cfg(feature = "file-system-monitor")]
    /// Watch file creations
    FileSystemMonitor,

    #[cfg(feature = "process-monitor")]
    /// Watch process events (fork/exec/exit)
    ProcessMonitor,

    #[cfg(feature = "network-monitor")]
    /// Watch network events
    NetworkMonitor,

    #[cfg(feature = "syscall-monitor")]
    /// Watch syscall events
    SyscallMonitor,
}

#[tokio::main]
async fn main() {
    match Probe::parse() {
        #[cfg(feature = "file-system-monitor")]
        Probe::FileSystemMonitor => run(file_system_monitor::program).await,

        #[cfg(feature = "process-monitor")]
        Probe::ProcessMonitor => run(process_monitor::program).await,

        #[cfg(feature = "network-monitor")]
        Probe::NetworkMonitor => run(network_monitor::program).await,

        #[cfg(feature = "syscall-monitor")]
        Probe::SyscallMonitor => run(syscall_monitor::program).await,
    };
}

async fn run<F, T, Fut>(program: F)
where
    F: Fn(BpfContext, mpsc::Sender<Result<T, ProgramError>>) -> Fut,
    Fut: Future<Output = Result<Program, ProgramError>>,
    T: std::fmt::Display,
{
    env_logger::builder()
        .filter(Some("probe"), log::LevelFilter::Info)
        .filter(Some("trace_point"), log::LevelFilter::Info)
        .init();
    #[cfg(debug_assertions)]
    let _stop_handle = bpf_common::trace_pipe::start();
    let (tx, mut rx) = mpsc::channel(100);
    let ctx = BpfContext::new(Pinning::Disabled, 512).unwrap();
    let _program = program(ctx, tx).await.expect("initialization failed");
    loop {
        tokio::select!(
            _ = tokio::signal::ctrl_c() => break,
            msg = rx.recv() => match msg {
                Some(Ok(msg)) => log::info!("{}", msg),
                Some(Err(err)) => { bpf_common::log_error("error", err); break }
                None => { log::info!("probe exited"); break; }
            }
        )
    }
}
