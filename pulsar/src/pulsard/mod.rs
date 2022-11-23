use anyhow::{anyhow, bail, ensure, Result};
use bpf_common::bpf_fs;
use engine_api::server::{self, EngineAPIContext, ServerConfig};
use pulsar_core::pdk::TaskLauncher;
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

#[derive(serde::Deserialize)]
struct GeneralConfig {
    //
}

pub async fn pulsar_daemon_run(
    options: &PulsarDaemonOpts,
    modules: Vec<Box<dyn TaskLauncher>>,
) -> Result<()> {
    log::trace!("Pulsar Daemon Options: {:?}", options);

    let is_root = unsafe { libc::getuid() } == 0;
    ensure!(is_root, "You must run this as root user!!!");

    bpf_fs::check_or_mount_bpf_fs()?;

    bump_memlock_rlimit()?;

    let config = if let Some(custom_file) = &options.config_file {
        PulsarConfig::with_custom_file(custom_file).await?
    } else {
        PulsarConfig::new().await?
    };

    let pulsar_daemon = start_daemon(modules, config.clone()).await?;

    let server_handle = {
        let pulsar_daemon = pulsar_daemon.clone();

        let server_config: ServerConfig = config.get_module_config(GENERAL_CONFIG).try_into()?;

        server::run_api_server(EngineAPIContext { pulsar_daemon }, server_config)?
    };

    let mut sig_int = signal(SignalKind::interrupt())?;
    let mut sig_term = signal(SignalKind::terminate())?;

    tokio::select! {
        _ = sig_int.recv() => log::trace!("SIGINT received"),
        _ = sig_term.recv() => log::trace!("SIGTERM received"),
    }

    log::info!("Terminating the Engine Api Server...");
    server_handle.stop().await;

    log::info!("Terminating Pulsar Daemon...");
    drop(pulsar_daemon);

    Ok(())
}

/// Bumps the rlimit for memlock up to full capacity.
/// This is required to load even reasonably sized eBPF maps.
fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!(anyhow!(std::io::Error::last_os_error()).context("Failed to increase rlimit"))
    }
    Ok(())
}
