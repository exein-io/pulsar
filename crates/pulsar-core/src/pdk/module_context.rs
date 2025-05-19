use std::time::UNIX_EPOCH;

use anyhow::{Context, Result};
use bpf_common::program::BpfContext;
use bpf_common::{Pid, program::BpfEvent, time::Timestamp};
use tokio::sync::{broadcast, mpsc};

use crate::event::{Header, Threat, Value};
use crate::{bus::Bus, pdk::PulsarDaemonHandle};

use super::process_tracker::ProcessInfo;
use super::{Event, Payload};
use super::{ModuleError, ModuleName, ModuleSignal, process_tracker::ProcessTrackerHandle};

/// Entrypoint to access all the functions available to the module.
#[derive(Clone)]
pub struct ModuleContext {
    module_name: ModuleName,
    bus: Bus,
    signal_sender: mpsc::Sender<ModuleSignal>,
    daemon_handle: PulsarDaemonHandle,
    process_tracker: ProcessTrackerHandle,
    bpf_context: BpfContext,
    tx_stop_cfg_recv: tokio::sync::mpsc::Sender<()>,
    tx_stop_event_recv: tokio::sync::mpsc::Sender<()>,
}

impl ModuleContext {
    /// Constructs a new [ModuleContext]`
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bus: Bus,
        module_name: ModuleName,
        signal_sender: mpsc::Sender<ModuleSignal>,
        daemon_handle: PulsarDaemonHandle,
        process_tracker: ProcessTrackerHandle,
        bpf_context: BpfContext,
        tx_stop_cfg_recv: tokio::sync::mpsc::Sender<()>,
        tx_stop_event_recv: tokio::sync::mpsc::Sender<()>,
    ) -> Self {
        Self {
            bus: bus.clone(),
            module_name: module_name.clone(),
            signal_sender,
            daemon_handle,
            process_tracker,
            bpf_context,
            tx_stop_cfg_recv,
            tx_stop_event_recv,
        }
    }

    /// Returns the module name
    pub fn module_name(&self) -> &str {
        &self.module_name
    }

    pub fn get_process_tracker(&self) -> ProcessTrackerHandle {
        self.process_tracker.clone()
    }

    /// Get an instance of the [`PulsarDaemonHandle`] to perform administration operations on modules.
    pub fn get_daemon_handle(&self) -> PulsarDaemonHandle {
        self.daemon_handle.clone()
    }

    pub fn get_bpf_context(&self) -> BpfContext {
        self.bpf_context.clone()
    }

    /// Send an event to the [`Bus`].
    pub fn send(&self, process: Pid, timestamp: Timestamp, payload: Payload) {
        self.send_internal(process, timestamp, payload, None)
    }

    /// Send an event which was caused by another event to the [`Bus`].
    /// The new event shares the source headers, but has a new payload.
    pub fn send_derived(&self, source: &Event, payload: Payload) {
        let header = source.header.clone();
        let _ = self.bus.send(Event { header, payload });
    }

    /// Send a threat to the [`Bus`].
    pub fn send_threat(
        &self,
        process: Pid,
        timestamp: Timestamp,
        description: String,
        extra: Option<Value>,
    ) {
        let threat = Threat {
            source: self.module_name.clone(),
            description,
            extra,
        };
        self.send_internal(process, timestamp, Payload::Empty, Some(threat))
    }

    /// Send a threat event which was caused by another event to the [`Bus`].
    /// The new event shares the source headers and the payload.
    pub fn send_threat_derived(
        &self,
        source_event: &Event,
        description: String,
        extra: Option<Value>,
    ) {
        let threat = Threat {
            source: self.module_name.clone(),
            description,
            extra,
        };

        let _ = self.bus.send(Event {
            header: Header {
                threat: Some(threat),
                ..source_event.header.clone()
            },
            payload: source_event.payload.clone(),
        });
    }

    /// Send a [`Payload`] to the [`Bus`] with optional [`Threat`].
    fn send_internal(
        &self,
        process: Pid,
        timestamp: Timestamp,
        payload: Payload,
        threat: Option<Threat>,
    ) {
        let tx = self.bus.clone();
        let process_tracker = self.process_tracker.clone();
        let module_name = self.module_name.clone();
        tokio::spawn(async move {
            let mut header = Header {
                source: module_name.clone(),
                threat,
                pid: process.as_raw(),
                timestamp: timestamp.into(),
                image: String::new(),
                parent_images: Vec::new(),
                uid: 0,
                gid: 0,
                parent_pid: 0,
                fork_time: UNIX_EPOCH,
                container: None,
            };
            match process_tracker.get(process, timestamp).await {
                Ok(ProcessInfo {
                    image,
                    parent_images,
                    ppid,
                    fork_time,
                    argv: _,
                    namespaces: _,
                    container,
                    uid,
                    gid,
                }) => {
                    header.image = image;
                    header.parent_images = parent_images;
                    header.parent_pid = ppid.as_raw();
                    header.fork_time = fork_time.into();
                    header.container = container;
                    header.uid = uid.as_raw();
                    header.gid = gid.as_raw();
                }
                Err(e) => {
                    // warning: check if this actually happens or not
                    log::error!(
                        target: &module_name,
                        "Process not found in tracker {process}: {e}"
                    );
                }
            }
            // get details from process tracker
            let event = Event { header, payload };
            tx.send(event)
        });
    }

    /// Raises unrecoverable errors from the module to the upper layer.
    ///
    /// Sending an error leads to a graceful shutdown of the module after [issue #7](https://github.com/Exein-io/pulsar/issues/7)
    /// will be closed.
    pub fn raise_error(&self, err: ModuleError) {
        // We don't want to make raise_error async, so we use try_send and ignore
        // the error. Since errors are fatal, it's not a problem to lose one when
        // the buffer is full.
        let _ = self.signal_sender.try_send(ModuleSignal::Error(err));
    }

    /// Raises warnings from the module to the upper layer.
    pub async fn raise_warning(&self, warning: String) {
        let _ = self
            .signal_sender
            .send(ModuleSignal::Warning(warning))
            .await;
    }

    pub(super) async fn stop_cfg_recv(&self) -> Result<(), ModuleError> {
        self.tx_stop_cfg_recv
            .send(())
            .await
            .context("cannot send sig stop cfg recv")?;

        Ok(())
    }

    pub(super) async fn stop_event_recv(&self) -> Result<(), ModuleError> {
        self.tx_stop_event_recv
            .send(())
            .await
            .context("cannot send sig stop event recv")?;
        Ok(())
    }
}

/// Convert row event and buffer to pulsar format
pub trait IntoPayload
where
    Self: Sized,
{
    type Error: std::error::Error + Send + Sync + 'static;
    /// Given a `bpf_common::BpfEvent<T>`, convert it to a pulsar Payload.
    fn try_into_payload(data: BpfEvent<Self>) -> Result<Payload, Self::Error>;
}

/// This allows to treat a ModuleSender as a bpf_common::Sender<T> for any T which
/// can be converted into a Payload. This allows probes to send Pulsar events despite
/// not knowing anything about Pulsar.
impl<T: IntoPayload> bpf_common::BpfSender<T> for ModuleContext {
    fn send(&mut self, data: Result<BpfEvent<T>, bpf_common::ProgramError>) {
        match data {
            Ok(data) => {
                let pid = data.pid;
                let timestamp = data.timestamp;
                match IntoPayload::try_into_payload(data) {
                    Ok(payload) => ModuleContext::send(self, pid, timestamp, payload),
                    Err(e) => self.raise_error(Box::new(e)),
                }
            }
            Err(e) => {
                self.raise_error(Box::new(e));
            }
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
