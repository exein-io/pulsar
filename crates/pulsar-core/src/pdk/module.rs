use std::{borrow::Cow, fmt, future::Future, ops::Deref, sync::Arc, time::UNIX_EPOCH};

use crate::{
    bus::{Bus, BusError},
    event::{Event, Header, Payload, Threat, Value},
};
use anyhow::Result;
use bpf_common::{program::BpfEvent, time::Timestamp, Pid};
use semver::Version;
use serde::{Deserialize, Serialize};
use tokio::sync::{
    broadcast::{self, error::RecvError},
    mpsc,
};
use validatron::Validatron;

use super::{
    process_tracker::{ProcessInfo, ProcessTrackerHandle},
    CleanExit, ModuleContext, ShutdownSignal,
};

pub type PulsarModuleTask = dyn Future<Output = Result<CleanExit, ModuleError>> + Send;

pub type ModuleStartFn = dyn Fn(ModuleContext, ShutdownSignal) -> Box<PulsarModuleTask> + Send;

/// Main implementation of [`TaskLauncher`] for creating Pulsar pluggable modules.
///
/// Contains informations to identify a module and the receipe to start its task.
pub struct PulsarModule {
    pub name: ModuleName,
    pub info: ModuleDetails,
    pub task_start_fn: Box<ModuleStartFn>,
}

impl PulsarModule {
    /// Constucts a new [`PulsarModule<B: Bus>`].
    pub fn new<N, F, Fut>(
        name: N,
        version: Version,
        enabled_by_default: bool,
        task_start_fn: F,
    ) -> Self
    where
        N: Into<ModuleName>,
        F: Fn(ModuleContext, ShutdownSignal) -> Fut,
        F: Send + Sync + 'static,
        Fut: Future<Output = Result<CleanExit, ModuleError>>,
        Fut: Send + 'static,
    {
        Self {
            name: name.into(),
            info: ModuleDetails {
                version,
                enabled_by_default,
            },
            task_start_fn: Box::new(move |ctx, shutdown| {
                let module = task_start_fn(ctx, shutdown);
                Box::new(module)
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Hash)]
pub struct ModuleName(Cow<'static, str>);

impl Deref for ModuleName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&'static str> for ModuleName {
    fn from(val: &'static str) -> ModuleName {
        ModuleName(std::borrow::Cow::Borrowed(val))
    }
}

impl From<String> for ModuleName {
    fn from(val: String) -> ModuleName {
        ModuleName(std::borrow::Cow::Owned(val))
    }
}

impl fmt::Display for ModuleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Validatron for ModuleName {
    fn get_class() -> validatron::ValidatronClass {
        Self::class_builder().primitive(
            Box::new(|s| Ok(ModuleName(Cow::Owned(s.to_string())))),
            Box::new(|op| match op {
                validatron::Operator::String(op) => match op {
                    validatron::StringOperator::StartsWith => {
                        Ok(Box::new(|a, b| a.0.as_ref().starts_with(b.0.as_ref())))
                    }
                    validatron::StringOperator::EndsWith => {
                        Ok(Box::new(|a, b| a.0.as_ref().ends_with(b.0.as_ref())))
                    }
                },
                validatron::Operator::Relational(op) => Ok(Box::new(move |a, b| op.apply(a, b))),
                _ => Err(validatron::ValidatronError::OperatorNotAllowedOnType(
                    op,
                    "ModuleName".to_string(),
                )),
            }),
        )
    }
}

impl TaskLauncher for PulsarModule {
    fn run(&self, ctx: ModuleContext, shutdown: ShutdownSignal) -> Box<PulsarModuleTask> {
        (self.task_start_fn)(ctx, shutdown)
    }

    fn name(&self) -> &ModuleName {
        &self.name
    }

    fn details(&self) -> &ModuleDetails {
        &self.info
    }
}

/// Contains module informations
#[derive(Debug, Clone)]
pub struct ModuleDetails {
    pub version: Version,
    pub enabled_by_default: bool,
    // pub author: String,
}

/// [`TaskLauncher`] is used as an internal trait to represent Pulsar modules.
///
/// Check instead [`PulsarModule`] for a module implementation.
///
/// The [`TaskLauncher::run`] method starts the module task and returns an pointer to a dynamic [`PulsarModuleTask`] trait object.
pub trait TaskLauncher: Send {
    /// Starts an asyncronous task in background a return a pointer to [`PulsarModuleTask`] to use it as an handle to stop the running task.
    fn run(&self, ctx: ModuleContext, shutdown: ShutdownSignal) -> Box<PulsarModuleTask>;

    /// Get the module name.
    fn name(&self) -> &ModuleName;

    // Get the module details.
    fn details(&self) -> &ModuleDetails;
}

/// Used to send events out from a module.
///
#[derive(Clone)]
pub struct ModuleSender {
    pub(crate) tx: Bus,
    pub(crate) module_name: ModuleName,
    pub(crate) process_tracker: ProcessTrackerHandle,
    pub(crate) signal_sender: SignalSender,
}

/// Raises unrecoverable errors from the module to the upper layer.
///
/// Sending an error leads to a graceful shutdown of the module after [issue #7](https://github.com/Exein-io/pulsar/issues/7)
/// will be closed.
pub type SignalSender = mpsc::Sender<ModuleSignal>;
pub type ModuleError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub enum ModuleSignal {
    Warning(String),
    Error(ModuleError),
}

impl ModuleSender {
    /// Send an event to the [`Bus`].
    pub fn send(&self, process: Pid, timestamp: Timestamp, payload: Payload) {
        self.send_internal(process, timestamp, payload, None)
    }

    /// Send an event which was caused by another event to the [`Bus`].
    /// The new event shares the source headers, but has a new payload.
    pub fn send_derived(&self, source: &Event, payload: Payload) {
        let header = source.header.clone();
        let _ = self.tx.send(Event { header, payload });
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

        let _ = self.tx.send(Event {
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
        let tx = self.tx.clone();
        let process_tracker = self.process_tracker.clone();
        let module_name = self.module_name.clone();
        tokio::spawn(async move {
            let mut header = Header {
                source: module_name.clone(),
                threat,
                pid: process.as_raw(),
                timestamp: timestamp.into(),
                image: String::new(),
                parent_pid: 0,
                fork_time: UNIX_EPOCH,
                container_id: None,
            };
            match process_tracker.get(process, timestamp).await {
                Ok(ProcessInfo {
                    image,
                    ppid,
                    fork_time,
                    argv: _,
                    namespaces: _,
                    container,
                }) => {
                    header.image = image;
                    header.parent_pid = ppid.as_raw();
                    header.fork_time = fork_time.into();
                    if let Some(container) = container {
                        header.container_id = Some(container.id);
                    }
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

    pub fn raise_error(&self, err: ModuleError) {
        // We don't want to make raise_error async, so we use try_send and ignore
        // the error. Since errors are fatal, it's not a problem to lose one when
        // the buffer is full.
        let _ = self.signal_sender.try_send(ModuleSignal::Error(err));
    }

    pub async fn raise_warning(&self, warning: String) {
        let _ = self
            .signal_sender
            .send(ModuleSignal::Warning(warning))
            .await;
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
impl<T: IntoPayload> bpf_common::BpfSender<T> for ModuleSender {
    fn send(&mut self, data: Result<BpfEvent<T>, bpf_common::ProgramError>) {
        match data {
            Ok(data) => {
                let pid = data.pid;
                let timestamp = data.timestamp;
                match IntoPayload::try_into_payload(data) {
                    Ok(payload) => ModuleSender::send(self, pid, timestamp, payload),
                    Err(e) => self.raise_error(Box::new(e)),
                }
            }
            Err(e) => {
                self.raise_error(Box::new(e));
            }
        }
    }
}

/// Used to receive events from outside of a module.
///
/// Returns data in form of [`Event`] objects.
#[derive(Debug)]
pub struct ModuleReceiver {
    pub(crate) rx: broadcast::Receiver<Arc<Event>>,
    pub(crate) module_name: ModuleName,
}

impl ModuleReceiver {
    /// Receive an [`Event`] from the [`Bus`].
    pub fn recv(&mut self) -> impl Future<Output = Result<Arc<Event>, BusError>> + '_ {
        receive_from_broadcast(&mut self.rx, &self.module_name)
    }
}

/// Receive an event from a [[broadcast::Receiver]]. Log a warning if we have lost messages
pub async fn receive_from_broadcast(
    rx: &mut broadcast::Receiver<Arc<Event>>,
    module_name: &str,
) -> Result<Arc<Event>, BusError> {
    let mut lost: u64 = 0;
    loop {
        match rx.recv().await {
            Ok(value) => {
                if lost > 0 {
                    log::warn!(
                        target: module_name,
                        "brodcast channel lagged {lost} messages",
                    );
                }
                return Ok(value);
            }
            Err(RecvError::Lagged(lagged)) => lost += lagged,
            Err(RecvError::Closed) => return Err(BusError::Stopped),
        }
    }
}
