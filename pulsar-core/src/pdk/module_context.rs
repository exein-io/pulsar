use anyhow::Result;
use bpf_common::program::BpfContext;
use tokio::sync::{broadcast, watch};

use crate::{
    bus::Bus,
    pdk::{ConfigValue, ErrorSender, ModuleReceiver, ModuleSender, PulsarDaemonHandle},
};

use super::{process_tracker::ProcessTrackerHandle, ConfigError, ModuleError, ModuleName};

/// Entrypoint to access all the functions available to the module.
#[derive(Clone)]
pub struct ModuleContext {
    module_name: ModuleName,
    cfg: watch::Receiver<ConfigValue>,
    bus: Bus,
    error_sender: ErrorSender,
    daemon_handle: PulsarDaemonHandle,
    process_tracker: ProcessTrackerHandle,
    bpf_context: BpfContext,
}

impl ModuleContext {
    /// Constructs a new `ModuleContext< B: Bus>`
    pub fn new(
        cfg: watch::Receiver<ConfigValue>,
        bus: Bus,
        module_name: ModuleName,
        error_sender: ErrorSender,
        daemon_handle: PulsarDaemonHandle,
        process_tracker: ProcessTrackerHandle,
        bpf_context: BpfContext,
    ) -> Self {
        Self {
            cfg,
            bus,
            module_name,
            error_sender,
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
            error_sender: self.error_sender.clone(),
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

    /// Get a [`tokio::sync::watch::Receiver`] of typed [`Result<T, String>`] for the module configuration.
    ///
    /// It can be used to receive always the last configuration without stop the module.
    ///
    /// It receives an [`Err`] if the configuration doesn't parse correctly.
    pub fn get_cfg<T>(&self) -> watch::Receiver<Result<T, ConfigError>>
    where
        T: Send + Sync + 'static,
        for<'foo> T: TryFrom<&'foo ConfigValue, Error = ConfigError>,
    {
        let mut rx_raw = self.cfg.clone();
        let initial_value = T::try_from(&rx_raw.borrow());
        let (tx_converted, rx_converted) = watch::channel(initial_value);

        tokio::spawn(async move {
            while rx_raw.changed().await.is_ok() {
                let new_value = T::try_from(&rx_raw.borrow());
                let _ = tx_converted.send_replace(new_value);
            }
        });

        rx_converted
    }

    pub fn get_bpf_context(&self) -> BpfContext {
        self.bpf_context.clone()
    }
}
