use anyhow::{Result, ensure};
use bpf_common::bpf_fs;
use engine_api::server::{self, EngineAPIContext};
use nix::unistd::geteuid;
use pulsar_core::bus::Bus;
use tokio::signal::unix::{SignalKind, signal};

use crate::cli::pulsard::PulsarDaemonOpts;

mod config;
mod daemon;
mod module_manager;

pub use config::PulsarConfig;
pub use daemon::PulsarDaemonStarter;
pub use module_manager::{ModuleManager, ModuleManagerHandle};

/// General configuration section for settings shared by all modules.
const GENERAL_CONFIG: &str = "pulsar";

pub async fn pulsar_daemon_run(
    options: &PulsarDaemonOpts,
    customize_starter: impl FnOnce(&mut PulsarDaemonStarter) -> Result<()>,
) -> Result<()> {
    log::trace!("Pulsar Daemon Options: {:?}", options);

    ensure!(geteuid().is_root(), "You must run this as root user!!!");

    bpf_fs::check_or_mount_bpf_fs()?;

    bpf_common::bump_memlock_rlimit()?;

    let config = if let Some(custom_file) = &options.config_file {
        PulsarConfig::with_custom_file(custom_file)?
    } else {
        PulsarConfig::new()?
    };

    // Initialize bus
    let bus = Bus::new();

    let mut starter = PulsarDaemonStarter::new(bus.clone(), config.clone()).await?;

    #[cfg(feature = "process-monitor")]
    starter.add_module(process_monitor::pulsar::ProcessMonitorModule)?;
    #[cfg(feature = "file-system-monitor")]
    starter.add_module(file_system_monitor::pulsar::FileSystemMonitorModule)?;
    #[cfg(feature = "network-monitor")]
    starter.add_module(network_monitor::pulsar::NetworkMonitorModule)?;
    #[cfg(feature = "threat-logger")]
    starter.add_module(threat_logger::ThreatLoggerModule)?;
    #[cfg(feature = "rules-engine")]
    starter.add_module(rules_engine::RuleEngineModule)?;
    #[cfg(feature = "desktop-notifier")]
    starter.add_module(desktop_notifier::DesktopNotifierModule)?;
    #[cfg(feature = "smtp-notifier")]
    starter.add_module(smtp_notifier::SmtpNotifierModule)?;

    customize_starter(&mut starter)?;

    let pulsar_daemon = starter.start_daemon().await?;

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
        log::info!("Terminating {} module...", module.name);
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
