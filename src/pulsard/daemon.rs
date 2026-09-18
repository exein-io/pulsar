use std::collections::HashMap;

use anyhow::{Result, bail};
use bpf_common::program::{BpfContext, BpfLogLevel, Pinning};

use pulsar_core::{
    bus::Bus,
    pdk::{
        ModuleOverview, ModuleStatus, PulsarDaemonCommand, PulsarDaemonError, PulsarDaemonHandle,
        PulsarModule,
        process_tracker::{ProcessTrackerHandle, start_process_tracker},
    },
};
use tokio::sync::mpsc;

use crate::pulsard::config::PulsarConfig;

use super::module_manager::{ModuleManagerHandle, create_module_manager};

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

        let perf_pages = config.pulsar.perf_pages;
        let btf_path = config.pulsar.btf_path.clone();
        let bpf_log_level = if cfg!(debug_assertions) {
            if log::max_level() >= log::Level::Debug {
                BpfLogLevel::Debug
            } else {
                BpfLogLevel::Error
            }
        } else {
            BpfLogLevel::Disabled
        };
        let bpf_context = BpfContext::new(Pinning::Enabled, perf_pages, btf_path, bpf_log_level)?;

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

        // A module with no section is configured as if it had an empty one.
        let section = self.config.take_module(&module_name).unwrap_or_default();
        let enabled = section.enabled.unwrap_or(T::DEFAULT_ENABLED);

        // A broken configuration is fatal for a module about to be started, and
        // only reported to whoever tries to start a disabled one later on.
        let config = match section.parse_config::<T::Config>(&module_name) {
            Ok(config) => Ok(config),
            Err(err) if enabled => return Err(err.into()),
            Err(err) => Err(err.to_string()),
        };

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
                    enabled,
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
        self.config.warn_unclaimed();

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
            if data.enabled {
                log::info!("Starting module {module_name}");
                // Start modules asynchronously because some of them maybe need to interact with the PulsarDaemon actor
                // through the ModuleContext
                tokio::spawn({
                    let handle = data.handle.clone();
                    async move {
                        if let Err(err_msg) = handle.start().await {
                            log::error!("{err_msg}");
                        };
                    }
                });
            }
        }

        let daemon = PulsarDaemon {
            modules: self.modules,
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
pub struct PulsarDaemon {
    modules: HashMap<String, ModuleData>,
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
        }
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
    enabled: bool,
    handle: ModuleManagerHandle,
}
