use anyhow::{ensure, Result};
use ebpf_common::bpf_fs;
use engine_api::server::{self, EngineAPIContext};
use nix::unistd::geteuid;
use pulsar_core::{bus::Bus, pdk::TaskLauncher};
use tokio::signal::unix::{signal, SignalKind};

use crate::cli::pulsard::PulsarDaemonOpts;

mod config;
mod daemon;
mod module_manager;

use daemon::start_daemon;

pub use config::PulsarConfig;
pub use daemon::PulsarDaemon;
pub use module_manager::{ModuleManager, ModuleManagerHandle};

/// General configuration section for settings shared by all modules.
const GENERAL_CONFIG: &str = "pulsar";

pub async fn pulsar_daemon_run(
    options: &PulsarDaemonOpts,
    modules: Vec<Box<dyn TaskLauncher>>,
) -> Result<()> {
    log::trace!("Pulsar Daemon Options: {:?}", options);

    ensure!(geteuid().is_root(), "You must run this as root user!!!");

    bpf_fs::check_or_mount_bpf_fs()?;

    ebpf_common::bump_memlock_rlimit()?;

    let config = if let Some(custom_file) = &options.config_file {
        PulsarConfig::with_custom_file(custom_file)?
    } else {
        PulsarConfig::new()?
    };

    // Initialize bus
    let bus = Bus::new();

    let pulsar_daemon = start_daemon(bus.clone(), modules, config.clone()).await?;

    let server_handle = {
        let pulsar_daemon = pulsar_daemon.clone();

        let general_config = config.get_module_config(GENERAL_CONFIG).unwrap_or_default();
        let custom_socket_path = general_config.get_raw("api_socket_path");

        server::run_api_server(EngineAPIContext { bus, pulsar_daemon }, custom_socket_path)?
    };

    let mut sig_int = signal(SignalKind::interrupt())?;
    let mut sig_term = signal(SignalKind::terminate())?;
    let mut sig_hup = signal(SignalKind::hangup())?;

    tokio::select! {
        _ = sig_int.recv() => log::trace!("SIGINT received"),
        _ = sig_term.recv() => log::trace!("SIGTERM received"),
        _ = sig_hup.recv() => log::trace!("SIGHUP received"),
    }

    log::info!("Terminating the Engine Api Server...");
    server_handle.stop().await;

    log::info!("Terminating Pulsar Daemon...");
    for module in pulsar_daemon.modules().await {
        if let Err(err) = pulsar_daemon.stop(module.name.clone()).await {
            log::warn!(
                "Module {} didn't respond to shutdown signal. Forcing shutdown.\n{:?}",
                module.name,
                err
            )
        }
    }

    Ok(())
}
