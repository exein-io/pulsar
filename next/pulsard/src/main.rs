//! `pulsard-next`: the prototype daemon, next to `pulsard`. Needs root.

use std::path::PathBuf;

use clap::Parser;
use next_core::{Oss, Pulsar};
use next_pulsard::{Config, OssDefaults};
use tokio::signal::unix::{SignalKind, signal};

#[derive(Parser)]
struct Args {
    /// pulsar.toml; defaults apply without it.
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

    let running = Pulsar::<Oss>::builder(config.core()?)
        .oss_defaults(&config)?
        .build()
        .await?;
    log::info!("pulsard-next running");
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
