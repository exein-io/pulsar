use std::future::Future;

use bpf_common::{
    Program, ProgramError,
    program::{BpfContext, BpfEvent, BpfLogLevel, Pinning},
};
use clap::{Parser, Subcommand};
use pulsar_core::pdk::IntoPayload;
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
#[clap(name = "probe")]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    verbose: bool,
    #[clap(subcommand)]
    probe: Probe,
}

/// Test runner for eBPF programs
#[allow(clippy::enum_variant_names)]
#[derive(Subcommand, Debug)]
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
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    match args.probe {
        #[cfg(feature = "file-system-monitor")]
        Probe::FileSystemMonitor => run(args, file_system_monitor::program).await,

        #[cfg(feature = "process-monitor")]
        Probe::ProcessMonitor => run(args, process_monitor::program).await,

        #[cfg(feature = "network-monitor")]
        Probe::NetworkMonitor => run(args, network_monitor::program).await,
    };
}

async fn run<F, T, Fut>(args: Args, program: F)
where
    F: Fn(BpfContext, mpsc::Sender<Result<BpfEvent<T>, ProgramError>>) -> Fut,
    Fut: Future<Output = Result<Program, ProgramError>>,
    T: IntoPayload,
{
    env_logger::builder()
        .filter(Some("probe"), log::LevelFilter::Info)
        .filter(Some("trace_pipe"), log::LevelFilter::Info)
        .init();
    #[cfg(debug_assertions)]
    let _stop_handle = bpf_common::trace_pipe::start().await;
    let (tx, mut rx) = mpsc::channel(100);
    let log_level = if args.verbose {
        BpfLogLevel::Debug
    } else {
        BpfLogLevel::Error
    };
    let ctx = BpfContext::new(Pinning::Disabled, 512, log_level).unwrap();
    let _program = program(ctx, tx).await.expect("initialization failed");
    loop {
        tokio::select!(
            _ = tokio::signal::ctrl_c() => break,
            msg = rx.recv() => match msg {
                Some(Ok(msg)) => log::info!("{}", T::try_into_payload(msg).unwrap()),
                Some(Err(err)) => { bpf_common::log_error("error", err); break }
                None => { log::info!("probe exited"); break; }
            }
        )
    }
}
