//! `pulsard-example`: Pulsar with an extension, built the way
//! pulsar-enterprise would be, from public APIs only. Needs root.
//!
//! The extension adds a probe that counts syscalls per process, its payload
//! and threat kind, a detector, a reporter and a rule (`rules/`). Its rule is
//! loaded with the others when `rules_path` in the configuration covers it.

mod detector;
mod probe;
mod reporter;
mod schema;
mod syscalls;

use std::path::PathBuf;

use clap::Parser;
use next_core::Pulsar;
use next_pulsard::{Config, OssDefaults};
use tokio::signal::unix::{SignalKind, signal};

use crate::{detector::AnomalyStub, probe::SyscallProbe, reporter::PlatformStub, schema::Ext};

/// Its own, so it can run next to pulsard-next.
const PIN_DIR: &str = "/sys/fs/bpf/pulsar-example/v1";

#[derive(Parser)]
struct Args {
    /// pulsar.toml; defaults apply without it. `daemon.pin_dir` is ignored.
    #[arg(long, short)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    let config = match &args.config {
        Some(path) => Config::load(path)?,
        None => Config::default(),
    };
    let mut core = config.core()?;
    core.loader.pin_dir = PathBuf::from(PIN_DIR);

    let running = Pulsar::<Ext>::builder(core)
        .oss_defaults(&config)?
        .probe(SyscallProbe)
        .detector(AnomalyStub)
        .reporter(PlatformStub)
        .build()
        .await?;
    log::info!("pulsard-example running");
    let stats = running.run(shutdown_signal()).await?;
    log::info!("stopped: {stats:?}");
    Ok(())
}

async fn shutdown_signal() {
    let mut terminate = signal(SignalKind::terminate()).expect("installing SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}
