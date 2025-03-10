use std::sync::Arc;

use bpf_common::program::BpfContext;
use pulsar_core::bus::Bus;
use pulsar_core::pdk::process_tracker::ProcessTrackerHandle;
use pulsar_core::pdk::{
    CleanExit, Event, ModuleConfig, ModuleContext, ModuleError, ModuleSignal, ModuleStatus,
    PulsarDaemonHandle, PulsarModule, ShutdownSender, ShutdownSignal,
};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;

/// Messages used for internal communication between [`ModuleManagerHandle`] and the underlying [`ModuleManager`] actor.
enum ModuleManagerCommand {
    StartModule {
        tx_reply: oneshot::Sender<Result<(), String>>,
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
/// Module is stored as pointer to dynamic [`TaskLauncher`] trait object. This is the "receipe" to start the module every time is requested by upper layer.
///
/// Once started, the running module will be managed through its [`PulsarModuleTask`] implementation.
pub struct ModuleManager<T: PulsarModule> {
    tx_sig: mpsc::Sender<ModuleSignal>,
    rx_sig: mpsc::Receiver<ModuleSignal>,
    rx_cmd: mpsc::Receiver<ModuleManagerCommand>,
    daemon_handle: PulsarDaemonHandle,
    process_tracker: ProcessTrackerHandle,
    bus: Bus,
    module: T,
    config: watch::Receiver<ModuleConfig>,
    status: ModuleStatus,
    running_task: Option<(ShutdownSender, JoinHandle<()>)>,
    bpf_context: BpfContext,
}

impl<T: PulsarModule> ModuleManager<T> {
    /// Construct a new [`ModuleManager`].
    fn new(
        rx_cmd: mpsc::Receiver<ModuleManagerCommand>,
        module: T,
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
            module,
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
                        T::MODULE_NAME
                    );

                    self.status = ModuleStatus::Failed(err.to_string());
                }
                Err(join_err) => {
                    let err_msg = format!(
                        "Error in module {}: {err}. Stopping module failed: {:?}",
                        T::MODULE_NAME,
                        join_err
                    );

                    log::error!("{err_msg}");

                    self.status = ModuleStatus::Failed(err_msg);
                }
            }
        } else {
            let err_msg = format!(
                "Error in module {err}. Stopping module {} failed: Module found in status: {:?}",
                T::MODULE_NAME,
                self.status
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
                    let _ = tx_reply.send(Ok(()));
                    return;
                }

                let module_config = match T::Config::try_from(&self.config.borrow()) {
                    Ok(mc) => mc,
                    Err(err) => {
                        self.status = ModuleStatus::Failed(format!("Configuration error: {err}"));
                        let err_msg = format!(
                            "Starting module {} failed, error in configuration: {err}",
                            T::MODULE_NAME
                        );
                        let _ = tx_reply.send(Err(err_msg));
                        return;
                    }
                };

                let (tx_stop_cfg_recv, rx_stop_cfg_recv) = mpsc::channel(1);
                let (tx_stop_event_recv, rx_stop_event_recv) = mpsc::channel(1);

                let mut ctx = ModuleContext::new(
                    self.bus.clone(),
                    T::MODULE_NAME.to_string().into(),
                    self.tx_sig.clone(),
                    self.daemon_handle.clone(),
                    self.process_tracker.clone(),
                    self.bpf_context.clone(),
                    tx_stop_cfg_recv,
                    tx_stop_event_recv,
                );

                let (state, extension) = match self.module.init_state(&module_config, &ctx).await {
                    Ok(s) => s,
                    Err(err) => {
                        self.status =
                            ModuleStatus::Failed(format!("State initializing error: {err}"));
                        let err_msg = format!(
                            "Starting module {} failed, error initializing the state: {err}",
                            T::MODULE_NAME
                        );
                        let _ = tx_reply.send(Err(err_msg));
                        return;
                    }
                };

                let rx_config = self.config.clone();
                let rx_event = self.bus.get_receiver();
                let (tx_shutdown, rx_shutdown) = ShutdownSignal::new();

                let tx_sig = self.tx_sig.clone();

                // Check error and forward to this module manager actor
                let join_handle = tokio::spawn(async move {
                    let res = run_module_loop::<T>(
                        module_config,
                        state,
                        extension,
                        rx_config,
                        rx_event,
                        rx_shutdown,
                        rx_stop_cfg_recv,
                        rx_stop_event_recv,
                        &mut ctx,
                    );
                    if let Err(err) = res.await {
                        let _ = tx_sig.send(ModuleSignal::Error(err)).await;
                    }
                });

                self.running_task = Some((tx_shutdown, join_handle));
                self.status = ModuleStatus::Running(Vec::new());

                // The `let _ =` ignores any errors when sending.
                //
                // This can happen if the `select!` macro is used
                // to cancel waiting for the response.
                let _ = tx_reply.send(Ok(()));
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
                                log::info!("Module {} exited", T::MODULE_NAME);

                                self.status = ModuleStatus::Stopped;

                                Ok(())
                            }
                            Err(err) => {
                                let err_msg =
                                    format!("Module {} exit failure: {err}", T::MODULE_NAME);

                                log::warn!("{err_msg}");

                                self.status = ModuleStatus::Failed(err.to_string());

                                Err(err.to_string())
                            }
                        }
                    }
                    ModuleStatus::Failed(_) => {
                        let err_msg = format!(
                            "Stopping module {} failed: Module found in status: {:?}",
                            T::MODULE_NAME,
                            self.status
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
        if let ModuleStatus::Running(warnings) = &mut self.status {
            warnings.push(warning);
        }
    }
}

impl<T: PulsarModule> Drop for ModuleManager<T> {
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
    pub async fn start(&self) -> Result<(), String> {
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
pub fn create_module_manager<T: PulsarModule + 'static>(
    bus: Bus,
    daemon_handle: PulsarDaemonHandle,
    process_tracker: ProcessTrackerHandle,
    module: T,
    config: watch::Receiver<ModuleConfig>,
    bpf_context: BpfContext,
) -> ModuleManagerHandle {
    // Create command channel used in the ModuleManagerHandle to send commands to the running ModuleManager actor
    let (tx_cmd, rx_cmd) = mpsc::channel(8);

    // Create the actor
    let actor = ModuleManager::new(
        rx_cmd,
        module,
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
async fn run_module_manager_actor<T: PulsarModule>(mut actor: ModuleManager<T>) {
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

#[allow(clippy::too_many_arguments)]
async fn run_module_loop<T: PulsarModule>(
    mut config: T::Config,
    mut state: T::State,
    mut extension: T::Extension,
    rx_config: watch::Receiver<ModuleConfig>,
    rx_event: broadcast::Receiver<Arc<Event>>,
    mut rx_shutdown: ShutdownSignal,
    mut rx_stop_cfg_recv: mpsc::Receiver<()>,
    mut rx_stop_event_recv: mpsc::Receiver<()>,
    ctx: &mut ModuleContext,
) -> Result<CleanExit, ModuleError> {
    // Make Configuration and Event Receivers optional allowing to be dropped
    // in case we receive the corresponding signals from the default implementation
    // of the [`pulsar_core::pdk::PulsarModule`] trait
    let mut rx_config = Some(rx_config);
    let mut rx_event = Some(rx_event);

    loop {
        tokio::select! {
            // Futures need to polled in a specific order
            biased;
            // Shutdown
            r = rx_shutdown.recv() => {
                T::graceful_stop(state).await?;
                return r
            },
            // Stop event receiver
            _ = rx_stop_event_recv.recv() => {
                // Drop the Event Receiver and replace it with None
                rx_event = None
            }
            // Stop config receiver
            _ = rx_stop_cfg_recv.recv() => {
                // Drop the Configuration Receiver and replace it with None
                rx_config = None
            }
            // Extra action
            t_output = T::trigger(&mut extension) => {
                let t_output = t_output?;
                T::action(&t_output, &config, &mut state, ctx).await?
            }
            // New config
            rx_config = async {
                match &mut rx_config {
                    Some(rx_config) => {
                        let change = rx_config.changed().await;
                        // This can't fail because the sender half of this channel is never dropped.
                        // Its lifetime is bound to PulsarConfig in `pulsar::pulsard::pulsar_daemon_run`
                        change.expect("Config sender dropped");
                        rx_config
                    },
                    None => std::future::pending().await,
                }
            } => {
                config = T::Config::try_from(&rx_config.borrow())?;
                T::on_config_change(&config, &mut state, ctx).await?;
            }
            // Incoming event
            event = async {
                match &mut rx_event {
                    Some(rx_event) => pulsar_core::pdk::receive_from_broadcast(rx_event, ctx.module_name()).await,
                    None => std::future::pending().await,
                }
            } => {
                let event = event.expect("no more events");
                T::on_event(&event, &config,  &mut state, ctx).await?;
            }
        }
    }
}
