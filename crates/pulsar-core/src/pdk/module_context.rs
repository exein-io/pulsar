use std::marker::PhantomData;

use anyhow::Result;
use ebpf_common::program::EbpfContext;
use tokio::sync::{broadcast, watch};

use crate::{
    bus::Bus,
    pdk::{ModuleConfig, ModuleReceiver, ModuleSender, PulsarDaemonHandle, SignalSender},
};

use super::{process_tracker::ProcessTrackerHandle, ConfigError, ModuleError, ModuleName};

/// Entrypoint to access all the functions available to the module.
#[derive(Clone)]
pub struct ModuleContext {
    module_name: ModuleName,
    cfg: watch::Receiver<ModuleConfig>,
    bus: Bus,
    signal_sender: SignalSender,
    daemon_handle: PulsarDaemonHandle,
    process_tracker: ProcessTrackerHandle,
    bpf_context: EbpfContext,
}

impl ModuleContext {
    /// Constructs a new `ModuleContext< B: Bus>`
    pub fn new(
        cfg: watch::Receiver<ModuleConfig>,
        bus: Bus,
        module_name: ModuleName,
        signal_sender: SignalSender,
        daemon_handle: PulsarDaemonHandle,
        process_tracker: ProcessTrackerHandle,
        bpf_context: EbpfContext,
    ) -> Self {
        Self {
            cfg,
            bus,
            module_name,
            signal_sender,
            daemon_handle,
            process_tracker,
            bpf_context,
        }
    }
}

#[derive(Debug)]
pub struct CleanExit(());

pub struct ShutdownSignal {
    tx: broadcast::Sender<()>,
    rx: broadcast::Receiver<()>,
}

impl Clone for ShutdownSignal {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            rx: self.tx.subscribe(),
        }
    }
}

impl ShutdownSignal {
    pub fn new() -> (ShutdownSender, ShutdownSignal) {
        let (tx, rx) = broadcast::channel(1);
        (ShutdownSender(tx.clone()), ShutdownSignal { tx, rx })
    }

    pub async fn recv(&mut self) -> Result<CleanExit, ModuleError> {
        let _ = self.rx.recv().await;
        Ok(CleanExit(()))
    }
}

pub struct ShutdownSender(broadcast::Sender<()>);

impl ShutdownSender {
    pub fn send_signal(self) {
        let _ = self.0.send(());
    }
}

impl ModuleContext {
    /// Get an instance of [`ModuleSender`] to send [`crate::event::Payload`] objects to the [`Bus`].
    pub fn get_sender(&self) -> ModuleSender {
        ModuleSender {
            tx: self.bus.get_sender(),
            module_name: self.module_name.to_owned(),
            process_tracker: self.process_tracker.clone(),
            signal_sender: self.signal_sender.clone(),
        }
    }

    pub fn get_process_tracker(&self) -> ProcessTrackerHandle {
        self.process_tracker.clone()
    }

    /// Get an instance of [`ModuleReceiver`] to receive [`crate::event::Event`] objects from the [`Bus`].
    pub fn get_receiver(&self) -> ModuleReceiver {
        ModuleReceiver {
            rx: self.bus.get_receiver(),
            module_name: self.module_name.to_owned(),
        }
    }

    /// Get an instance of the [`PulsarDaemonHandle`] to perform administration operations on modules.
    pub fn get_daemon_handle(&self) -> PulsarDaemonHandle {
        self.daemon_handle.clone()
    }

    pub fn get_config<T: Send + Sync + 'static>(&self) -> ModuleConfigReceiver<T> {
        ModuleConfigReceiver::new(self.cfg.clone())
    }

    pub fn get_bpf_context(&self) -> EbpfContext {
        self.bpf_context.clone()
    }
}

#[derive(Clone)]
pub struct ModuleConfigReceiver<T: Send + Sync + 'static> {
    rx: watch::Receiver<ModuleConfig>,
    _config: PhantomData<T>,
}

impl<T: Send + Sync + 'static> ModuleConfigReceiver<T> {
    pub fn new(rx: watch::Receiver<ModuleConfig>) -> Self {
        Self {
            rx,
            _config: PhantomData,
        }
    }

    pub fn borrow(&self) -> watch::Ref<'_, ModuleConfig> {
        self.rx.borrow()
    }

    /// Get a [`Result<T, String>`] for the module configuration.
    ///
    /// It can be used to receive the lastest parsed configuration.
    /// T Must implement [`TryFrom<&ModuleConfig, Error = ConfigError>`]
    ///
    /// It receives an [`Err`] if the configuration doesn't parse correctly.
    pub fn read(&self) -> Result<T, ConfigError>
    where
        for<'foo> T: TryFrom<&'foo ModuleConfig, Error = ConfigError>,
    {
        T::try_from(&self.rx.borrow())
    }

    /// Get notified of a configuration change.
    pub async fn changed(&mut self) {
        // This can't fail because the sender half of this channel is never dropped.
        // Its lifetime is bound to PulsarConfig in `pulsar::pulsard::pulsar_daemon_run`
        self.rx.changed().await.expect("Config sender dropped");
    }
}
