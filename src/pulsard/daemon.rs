use std::collections::HashMap;

use anyhow::{bail, Result};
use bpf_common::program::{BpfContext, BpfLogLevel, Pinning, PERF_PAGES_DEFAULT};

use pulsar_core::{
    bus::Bus,
    pdk::{
        process_tracker::{start_process_tracker, ProcessTrackerHandle},
        ModuleConfig, ModuleOverview, ModuleStatus, PulsarDaemonCommand, PulsarDaemonError,
        PulsarDaemonHandle, PulsarModule,
    },
};
use tokio::sync::mpsc;

use crate::pulsard::{config::PulsarConfig, GENERAL_CONFIG};

use super::module_manager::{create_module_manager, ModuleManagerHandle};

pub struct PulsarDaemonStarter {
    bus: Bus,
    config: PulsarConfig,
    modules: HashMap<String, ModuleData>,
    tx_modules_cmd: mpsc::Sender<PulsarDaemonCommand>,
    rx_modules_cmd: mpsc::Receiver<PulsarDaemonCommand>,
    process_tracker: ProcessTrackerHandle,
    bpf_context: BpfContext,
}

impl PulsarDaemonStarter {
    pub(super) async fn new(bus: Bus, config: PulsarConfig) -> anyhow::Result<Self> {
        let (tx_modules_cmd, rx_modules_cmd) = mpsc::channel(8);

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

        Ok(Self {
            bus,
            config,
            modules: Default::default(),
            tx_modules_cmd,
            rx_modules_cmd,
            process_tracker,
            bpf_context,
        })
    }

    pub fn add_module<T: PulsarModule + 'static>(&mut self, module: T) -> anyhow::Result<()> {
        let daemon_handle = PulsarDaemonHandle {
            tx_cmd: self.tx_modules_cmd.clone(),
        };

        let module_name = T::MODULE_NAME.to_owned();

        let config = self.config.get_watched_module_config(&module_name);

        let module_handle = create_module_manager(
            self.bus.clone(),
            daemon_handle,
            self.process_tracker.clone(), // TODO: move to module
            module,
            config,
            self.bpf_context.clone(),
        );

        if self
            .modules
            .insert(
                module_name.to_string(),
                ModuleData {
                    enabled_by_default: T::DEFAULT_ENABLED,
                    handle: module_handle,
                },
            )
            .is_some()
        {
            bail!(
                "Error creating modules: module {} already present",
                module_name
            )
        }

        Ok(())
    }

    /// Create and start a [`PulsarDaemon`] actor to manage the underlying Pulsar modules.
    ///
    /// Returns the [`PulsarDaemonHandle`] that can be used to interact with the [`PulsarDaemon`] actor.
    pub(super) async fn start_daemon(self) -> anyhow::Result<PulsarDaemonHandle> {
        #[cfg(debug_assertions)]
        let trace_pipe_handle = bpf_common::trace_pipe::start().await;

        // This act as a "weak" PulsarDaemonHandle to be used inside modules.
        //
        // [`run_daemon_actor`] relies on the [`std::ops::Drop`] of the outside PulsarDaemonHandle to stop PulsarDaemon actor.
        let daemon_handle = PulsarDaemonHandle {
            tx_cmd: self.tx_modules_cmd,
        };

        // Start modules
        for (module_name, data) in &self.modules {
            let module_config = self.config.get_watched_module_config(module_name);
            let is_enabled = module_config
                .borrow()
                .with_default("enabled", data.enabled_by_default)
                .unwrap_or(false);

            if is_enabled {
                log::info!("Starting module {module_name}");
                if let Err(err_msg) = data.handle.start().await {
                    log::error!("{err_msg}");
                };
            }
        }

        let daemon = PulsarDaemon {
            modules: self.modules,
            config: self.config,
            rx_cmd: self.rx_modules_cmd,
            #[cfg(debug_assertions)]
            trace_pipe_handle,
        };

        // Start daemon
        tokio::spawn(run_daemon_actor(daemon));

        log::debug!("Daemon started");

        Ok(daemon_handle)
    }
}

/// Main component of Pulsar framework. It's implemented with the actor pattern and its entrypoint is its [`PulsarDaemonHandle`]
///
/// Contains references to all loaded modules. Each module is wrapped inside a [`super::ModuleManager`] actor to manage its lifecycle.
///
/// [`PulsarDaemon`] can:
/// - administrate loaded modules using the relative [`ModuleManagerHandle`]
/// - manage module configurations using [`PulsarConfig`]
pub struct PulsarDaemon {
    modules: HashMap<String, ModuleData>,
    config: PulsarConfig,
    rx_cmd: mpsc::Receiver<PulsarDaemonCommand>,
    #[cfg(debug_assertions)]
    #[allow(unused)]
    trace_pipe_handle: bpf_common::trace_pipe::StopHandle,
}

impl PulsarDaemon {
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
        let data = self
            .modules
            .get(module_name)
            .ok_or_else(|| PulsarDaemonError::ModuleNotFound(module_name.to_string()))?;
        Ok(data.handle.status().await)
    }

    /// Start a module.
    async fn start(&self, module_name: &str) -> Result<(), PulsarDaemonError> {
        let data = self
            .modules
            .get(module_name)
            .ok_or_else(|| PulsarDaemonError::ModuleNotFound(module_name.to_string()))?;

        data.handle
            .start()
            .await
            .map_err(PulsarDaemonError::StartError)
    }

    /// Restart a module.
    async fn restart(&self, module_name: &str) -> Result<(), PulsarDaemonError> {
        let data = self
            .modules
            .get(module_name)
            .ok_or_else(|| PulsarDaemonError::ModuleNotFound(module_name.to_string()))?;
        data.handle
            .stop()
            .await
            .map_err(PulsarDaemonError::StopError)?;

        data.handle
            .start()
            .await
            .map_err(PulsarDaemonError::StartError)
    }

    /// Stop a module.
    async fn stop(&self, module_name: &str) -> Result<(), PulsarDaemonError> {
        let data = self
            .modules
            .get(module_name)
            .ok_or_else(|| PulsarDaemonError::ModuleNotFound(module_name.to_string()))?;

        data.handle
            .stop()
            .await
            .map_err(PulsarDaemonError::StopError)
    }

    /// Get loaded module list.
    async fn modules(&self) -> Vec<ModuleOverview> {
        let mut v = Vec::new();
        for (name, data) in self.modules.iter() {
            v.push(ModuleOverview {
                name: name.clone(),
                status: data.handle.status().await,
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

/// Run a [`PulsarDaemon`] actor.
async fn run_daemon_actor(mut actor: PulsarDaemon) {
    loop {
        tokio::select!(
            cmd = actor.rx_cmd.recv() => match cmd {
                Some(cmd) => actor.handle_cmd(cmd).await,
                None => return
            },
        )
    }
}

struct ModuleData {
    enabled_by_default: bool,
    handle: ModuleManagerHandle,
}
