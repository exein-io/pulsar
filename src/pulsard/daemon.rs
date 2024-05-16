use std::collections::HashMap;

use anyhow::{bail, Result};
use bpf_common::program::{BpfContext, BpfLogLevel, Pinning, PERF_PAGES_DEFAULT};

use pulsar_core::{
    bus::Bus,
    pdk::{
        process_tracker::start_process_tracker, ModuleConfig, ModuleDetails, ModuleOverview,
        ModuleStatus, PulsarDaemonCommand, PulsarDaemonError, PulsarDaemonHandle, TaskLauncher,
    },
};
use tokio::sync::mpsc;

use crate::pulsard::{config::PulsarConfig, GENERAL_CONFIG};

use super::module_manager::{create_module_manager, ModuleManagerHandle};

/// Main component of Pulsar framework. It's implemented with the actor pattern and its entrypoint is its [`PulsarDaemonHandle`]
///
/// Contains references to all loaded modules. Each module is wrapped inside a [`super::ModuleManager`] actor to manage its lifecycle.
///
/// [`PulsarDaemon`] can:
/// - administrate loaded modules using the relative [`ModuleManagerHandle`]
/// - manage module configurations using [`PulsarConfig`]
pub struct PulsarDaemon {
    modules: HashMap<String, (ModuleDetails, ModuleManagerHandle)>,
    config: PulsarConfig,
    rx_cmd: mpsc::Receiver<PulsarDaemonCommand>,
    rx_modules_cmd: mpsc::Receiver<PulsarDaemonCommand>,
    #[cfg(debug_assertions)]
    #[allow(unused)]
    trace_pipe_handle: bpf_common::trace_pipe::StopHandle,
}

impl PulsarDaemon {
    /// Construct a new [`PulsarDaemon`]
    async fn new(
        bus: Bus,
        modules: Vec<Box<dyn TaskLauncher>>,
        config: PulsarConfig,
        rx_cmd: mpsc::Receiver<PulsarDaemonCommand>,
    ) -> anyhow::Result<Self> {
        let (tx_modules_cmd, rx_modules_cmd) = mpsc::channel(8);

        // This act as a "weak" PulsarDaemonHandle to be used inside modules.
        //
        // [`run_daemon_actor`] relies on the [`std::ops::Drop`] of the outside PulsarDaemonHandle to stop PulsarDaemon actor.
        let daemon_handle = PulsarDaemonHandle {
            tx_cmd: tx_modules_cmd,
        };

        let mut m = HashMap::new();
        let process_tracker = start_process_tracker();

        let general_config = config.get_module_config(GENERAL_CONFIG).unwrap_or_default();
        let perf_pages = general_config.with_default("perf_pages", PERF_PAGES_DEFAULT)?;
        let bpf_log_level = if cfg!(debug_assertions) {
            if log::max_level() >= log::Level::Debug {
                BpfLogLevel::Debug
            } else {
                BpfLogLevel::Error
            }
        } else {
            BpfLogLevel::Disabled
        };
        let bpf_context = BpfContext::new(Pinning::Enabled, perf_pages, bpf_log_level)?;
        #[cfg(debug_assertions)]
        let trace_pipe_handle = bpf_common::trace_pipe::start().await;

        for task_launcher in modules {
            let module_name = task_launcher.name().to_owned();
            let module_details = task_launcher.details().to_owned();

            let config = config.get_watched_module_config(&module_name);
            let is_enabled = config
                .borrow()
                .with_default("enabled", module_details.enabled_by_default)
                .unwrap_or(false);
            let module_handle = create_module_manager(
                bus.clone(),
                daemon_handle.clone(),
                process_tracker.clone(),
                task_launcher,
                config,
                bpf_context.clone(),
            );
            if is_enabled {
                log::info!("Starting module {module_name}");
                module_handle.start().await;
            }
            // TODO: remove this once we've moved filtering policy and process
            // tracking to core
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            if m.insert(module_name.to_string(), (module_details, module_handle))
                .is_some()
            {
                bail!(
                    "Error creating modules: module {} already present",
                    module_name
                )
            }
        }

        log::debug!("Daemon started");

        Ok(Self {
            modules: m,
            config,
            rx_cmd,
            rx_modules_cmd,
            #[cfg(debug_assertions)]
            trace_pipe_handle,
        })
    }

    /// Handle commands coming from [`PulsarDaemonHandle`].
    async fn handle_cmd(&self, cmd: PulsarDaemonCommand) {
        match cmd {
            PulsarDaemonCommand::ModulesList { tx_reply } => {
                let _ = tx_reply.send(self.modules().await);
            }
            PulsarDaemonCommand::Status {
                tx_reply,
                module_name,
            } => {
                let _ = tx_reply.send(self.status(&module_name).await);
            }
            PulsarDaemonCommand::StartModule {
                tx_reply,
                module_name,
            } => {
                let _ = tx_reply.send(self.start(&module_name).await);
            }
            PulsarDaemonCommand::RestartModule {
                tx_reply,
                module_name,
            } => {
                let _ = tx_reply.send(self.restart(&module_name).await);
            }
            PulsarDaemonCommand::StopModule {
                tx_reply,

                module_name,
            } => {
                let _ = tx_reply.send(self.stop(&module_name).await);
            }
            PulsarDaemonCommand::GetConfiguration {
                tx_reply,
                module_name,
            } => {
                let _ = tx_reply.send(self.get_module_config(&module_name));
            }
            PulsarDaemonCommand::SetConfiguration {
                tx_reply,
                module_name,
                key,

                value,
            } => {
                let _ = tx_reply.send(self.update_config(&module_name, &key, &value));
            }
            PulsarDaemonCommand::Configs { tx_reply } => {
                let _ = tx_reply.send(self.get_configs());
            }
        }
    }

    /// Helper function to check if a module exists in the loaded modules list.
    fn contains_module(&self, module_name: &str) -> bool {
        self.modules.contains_key(module_name) || module_name == GENERAL_CONFIG
    }

    /// Get module status.
    async fn status(&self, module_name: &str) -> Result<ModuleStatus, PulsarDaemonError> {
        let (_, module_handle) = self
            .modules
            .get(module_name)
            .ok_or_else(|| PulsarDaemonError::ModuleNotFound(module_name.to_string()))?;
        Ok(module_handle.status().await)
    }

    /// Start a module.
    async fn start(&self, module_name: &str) -> Result<(), PulsarDaemonError> {
        let (_, module_handle) = self
            .modules
            .get(module_name)
            .ok_or_else(|| PulsarDaemonError::ModuleNotFound(module_name.to_string()))?;

        #[allow(clippy::unit_arg)]
        Ok(module_handle.start().await)
    }

    /// Restart a module.
    async fn restart(&self, module_name: &str) -> Result<(), PulsarDaemonError> {
        let (_, module_handle) = self
            .modules
            .get(module_name)
            .ok_or_else(|| PulsarDaemonError::ModuleNotFound(module_name.to_string()))?;
        module_handle
            .stop()
            .await
            .map_err(PulsarDaemonError::StopError)?;

        #[allow(clippy::unit_arg)]
        Ok(module_handle.start().await)
    }

    /// Stop a module.
    async fn stop(&self, module_name: &str) -> Result<(), PulsarDaemonError> {
        let (_, module_handle) = self
            .modules
            .get(module_name)
            .ok_or_else(|| PulsarDaemonError::ModuleNotFound(module_name.to_string()))?;

        module_handle
            .stop()
            .await
            .map_err(PulsarDaemonError::StopError)
    }

    /// Get loaded module list.
    async fn modules(&self) -> Vec<ModuleOverview> {
        let mut v = Vec::new();
        for (name, (details, handle)) in self.modules.iter() {
            v.push(ModuleOverview {
                name: name.clone(),
                version: details.version.clone(),
                status: handle.status().await,
            })
        }
        v
    }

    /// Get module configuration.
    fn get_module_config(&self, module_name: &str) -> Result<ModuleConfig, PulsarDaemonError> {
        if !self.contains_module(module_name) {
            return Err(PulsarDaemonError::ModuleNotFound(module_name.to_string()));
        }

        self.config.get_module_config(module_name).ok_or_else(|| {
            log::error!("Module found in task manager but configuration not found");

            PulsarDaemonError::ModuleNotFound(module_name.to_string())
        })
    }

    /// Get all configurations.
    fn get_configs(&self) -> Vec<(String, ModuleConfig)> {
        self.config.get_configs()
    }

    /// Update module configuration. It takes a key and value.
    fn update_config(
        &self,
        module_name: &str,
        key: &str,
        value: &str,
    ) -> Result<(), PulsarDaemonError> {
        if !self.contains_module(module_name) {
            return Err(PulsarDaemonError::ModuleNotFound(module_name.to_string()));
        }

        self.config
            .update_config(module_name, key, value)
            .map_err(PulsarDaemonError::ConfigurationUpdateError)
    }
}

/// Create and start a [`PulsarDaemon`] actor to manage the underlying Pulsar modules.
///
/// Returns the [`PulsarDaemonHandle`] that can be used to interact with the [`PulsarDaemon`] actor.
pub async fn start_daemon(
    bus: Bus,
    modules: Vec<Box<dyn TaskLauncher>>,
    config: PulsarConfig,
) -> anyhow::Result<PulsarDaemonHandle> {
    let (tx_cmd, rx_cmd) = mpsc::channel(8);

    let daemon_handle = PulsarDaemonHandle { tx_cmd };

    let daemon = PulsarDaemon::new(bus, modules, config, rx_cmd).await?;

    tokio::spawn(run_daemon_actor(daemon));

    Ok(daemon_handle)
}

/// Run a [`PulsarDaemon`] actor.
async fn run_daemon_actor(mut actor: PulsarDaemon) {
    loop {
        tokio::select!(
            cmd = actor.rx_cmd.recv() => match cmd {
                Some(cmd) => actor.handle_cmd(cmd).await,
                None => return
            },
            cmd = actor.rx_modules_cmd.recv() => match cmd {
                Some(cmd) => actor.handle_cmd(cmd).await,
                None => unreachable!()
            }
        )
    }
}
