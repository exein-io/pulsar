use bpf_common::program::BpfContext;
use pulsar_core::bus::Bus;
use pulsar_core::pdk::process_tracker::ProcessTrackerHandle;
use pulsar_core::pdk::{
    ModuleConfig, ModuleContext, ModuleError, ModuleSignal, ModuleStatus, PulsarDaemonHandle,
    PulsarModule, ShutdownSender, ShutdownSignal,
};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

/// Messages used for internal communication between [`ModuleManagerHandle`] and the underlying [`ModuleManager`] actor.
enum ModuleManagerCommand {
    StartModule {
        tx_reply: oneshot::Sender<()>,
    },
    StopModule {
        tx_reply: oneshot::Sender<Result<(), String>>,
    },
    GetStatus {
        tx_reply: oneshot::Sender<ModuleStatus>,
    },
}

/// Actor responsible of underlying module lifecycle.
///
/// Module is stored as a pulsar module with a pointer to dynamic [`Module`] trait object. This is the "receipe" to start the module every time is requested by upper layer.
///
/// Once started, the running module will be managed through its [`PulsarModuleTask`] implementation.
pub struct ModuleManager {
    tx_sig: mpsc::Sender<ModuleSignal>,
    rx_sig: mpsc::Receiver<ModuleSignal>,
    rx_cmd: mpsc::Receiver<ModuleManagerCommand>,
    daemon_handle: PulsarDaemonHandle,
    process_tracker: ProcessTrackerHandle,
    bus: Bus,
    pulsar_module: PulsarModule,
    config: watch::Receiver<ModuleConfig>,
    status: ModuleStatus,
    running_task: Option<(ShutdownSender, JoinHandle<()>)>,
    bpf_context: BpfContext,
}

impl ModuleManager {
    /// Construct a new [`ModuleManager`].
    fn new(
        rx_cmd: mpsc::Receiver<ModuleManagerCommand>,
        pulsar_module: PulsarModule,
        bus: Bus,
        config: watch::Receiver<ModuleConfig>,
        daemon_handle: PulsarDaemonHandle,
        process_tracker: ProcessTrackerHandle,
        bpf_context: BpfContext,
    ) -> Self {
        let (tx_sig, rx_sig) = mpsc::channel(8);
        Self {
            tx_sig,
            rx_sig,
            rx_cmd,
            pulsar_module,
            bus,
            config,
            status: ModuleStatus::Created,
            running_task: None,
            daemon_handle,
            process_tracker,
            bpf_context,
        }
    }

    /// Handle unrecoverable error coming from modules.
    ///
    /// It will stop the module through [`PulsarModuleTask::stop`] method.
    async fn handle_module_error(&mut self, err: ModuleError) {
        if let ModuleStatus::Running(_) = self.status {
            let (tx_shutdown, task) = self.running_task.take().unwrap();
            tx_shutdown.send_signal();
            let result = task.await;

            match result {
                Ok(_) => {
                    log::error!(
                        "Error in module {}. Module stopped. {err:?}",
                        self.pulsar_module.name
                    );

                    self.status = ModuleStatus::Failed(err.to_string());
                }
                Err(join_err) => {
                    let err_msg = format!(
                        "Error in module {}: {err}. Stopping module failed: {:?}",
                        self.pulsar_module.name, join_err
                    );

                    log::error!("{err_msg}");

                    self.status = ModuleStatus::Failed(err_msg);
                }
            }
        } else {
            let err_msg = format!(
                "Error in module {err}. Stopping module {} failed: Module found in status: {:?}",
                self.pulsar_module.name, self.status
            );

            log::error!("{err_msg}");

            self.status = ModuleStatus::Failed(err_msg);
        }
    }

    /// Handle commands coming from [`ModuleManagerHandle`].
    async fn handle_cmd(&mut self, cmd: ModuleManagerCommand) {
        match cmd {
            ModuleManagerCommand::StartModule { tx_reply } => {
                // Check if the  module is already running
                if let ModuleStatus::Running(_) = self.status {
                    let _ = tx_reply.send(());
                    return;
                }

                let ctx = ModuleContext::new(
                    self.config.clone(),
                    self.bus.clone(),
                    self.pulsar_module.name.clone(),
                    self.tx_sig.clone(),
                    self.daemon_handle.clone(),
                    self.process_tracker.clone(),
                    self.bpf_context.clone(),
                );
                let (tx_shutdown, rx_shutdown) = ShutdownSignal::new();

                let tx_sig = self.tx_sig.clone();

                let opt_module = (self.pulsar_module.setup_fn)(&ctx);

                // Check error and forward to this module manager actor
                let join_handle = tokio::spawn(async move {
                    if let Ok(mut module) = opt_module {
                        if let Err(err) = module.run(ctx, rx_shutdown).await {
                            let _ = tx_sig.send(ModuleSignal::Error(err)).await;
                        }
                    }
                });

                self.running_task = Some((tx_shutdown, join_handle));
                self.status = ModuleStatus::Running(Vec::new());

                // The `let _ =` ignores any errors when sending.
                //
                // This can happen if the `select!` macro is used
                // to cancel waiting for the response.
                let _ = tx_reply.send(());
            }
            ModuleManagerCommand::StopModule { tx_reply } => {
                let result = match self.status {
                    ModuleStatus::Created | ModuleStatus::Stopped => Ok(()),
                    ModuleStatus::Running(_) => {
                        let (tx_shutdown, task) = self.running_task.take().unwrap();
                        tx_shutdown.send_signal();
                        let result = task.await;
                        match result {
                            Ok(()) => {
                                log::info!("Module {} exited", self.pulsar_module.name);

                                self.status = ModuleStatus::Stopped;

                                Ok(())
                            }
                            Err(err) => {
                                let err_msg = format!(
                                    "Module {} exit failure: {err}",
                                    self.pulsar_module.name
                                );

                                log::warn!("{err_msg}");

                                self.status = ModuleStatus::Failed(err.to_string());

                                Err(err.to_string())
                            }
                        }
                    }
                    ModuleStatus::Failed(_) => {
                        let err_msg = format!(
                            "Stopping module {} failed: Module found in status: {:?}",
                            self.pulsar_module.name, self.status
                        );
                        Err(err_msg)
                    }
                };

                // The `let _ =` ignores any errors when sending.
                //
                // This can happen if the `select!` macro is used
                // to cancel waiting for the response.
                let _ = tx_reply.send(result);
            }
            ModuleManagerCommand::GetStatus { tx_reply } => {
                // The `let _ =` ignores any errors when sending.
                //
                // This can happen if the `select!` macro is used
                // to cancel waiting for the response.
                let _ = tx_reply.send(self.status.clone());
            }
        }
    }

    pub fn add_warning(&mut self, warning: String) {
        if let ModuleStatus::Running(ref mut warnings) = &mut self.status {
            warnings.push(warning);
        }
    }
}

impl Drop for ModuleManager {
    /// Stop the task when dropped
    fn drop(&mut self) {
        if let ModuleStatus::Running(_) = self.status {
            self.running_task.take().unwrap().0.send_signal();
        }
    }
}

/// Handle to a running [`ModuleManager`].
///
/// Provides module status and lifecycle management functionalities.
#[derive(Clone)]
pub struct ModuleManagerHandle {
    tx_cmd: mpsc::Sender<ModuleManagerCommand>,
}

impl ModuleManagerHandle {
    /// Get module status
    pub async fn status(&self) -> ModuleStatus {
        let (send, recv) = oneshot::channel();
        let msg = ModuleManagerCommand::GetStatus { tx_reply: send };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check the
        // failure twice.
        let _ = self.tx_cmd.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    /// Start the module
    pub async fn start(&self) {
        let (send, recv) = oneshot::channel();
        let msg = ModuleManagerCommand::StartModule { tx_reply: send };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check the
        // failure twice.
        let _ = self.tx_cmd.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    /// Stop the module
    pub async fn stop(&self) -> Result<(), String> {
        let (send, recv) = oneshot::channel();
        let msg = ModuleManagerCommand::StopModule { tx_reply: send };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check the
        // failure twice.
        let _ = self.tx_cmd.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }
}

/// Create and start a [`ModuleManager`] actor to manage the specific Pulsar module.
///
/// Returns the [`ModuleManagerHandle`] that can be used to interact with the [`ModuleManager`] actor.
pub fn create_module_manager(
    bus: Bus,
    daemon_handle: PulsarDaemonHandle,
    process_tracker: ProcessTrackerHandle,
    pulsar_module: PulsarModule,
    config: watch::Receiver<ModuleConfig>,
    bpf_context: BpfContext,
) -> ModuleManagerHandle {
    // Create command channel used in the ModuleManagerHandle to send commands to the running ModuleManager actor
    let (tx_cmd, rx_cmd) = mpsc::channel(8);

    // Create the actor
    let actor = ModuleManager::new(
        rx_cmd,
        pulsar_module,
        bus,
        config,
        daemon_handle,
        process_tracker,
        bpf_context,
    );

    // Start the ModuleManager actor as an asynchronous task
    tokio::spawn(run_module_manager_actor(actor));

    ModuleManagerHandle { tx_cmd }
}

/// Run a [`ModuleManager`] actor.
async fn run_module_manager_actor(mut actor: ModuleManager) {
    loop {
        tokio::select!(
            Some(sig) = actor.rx_sig.recv() => match sig {
                    ModuleSignal::Error(err) => actor.handle_module_error(err).await,
                    ModuleSignal::Warning(warn) => actor.add_warning(warn),
            },
            cmd = actor.rx_cmd.recv() => match cmd {
                Some(cmd) => actor.handle_cmd(cmd).await,
                None => return
            }
        )
    }
}
