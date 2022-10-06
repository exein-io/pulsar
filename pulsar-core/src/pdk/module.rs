use std::{borrow::Cow, fmt, future::Future, ops::Deref, sync::Arc, time::UNIX_EPOCH};

use crate::{
    bus::{Bus, BusError},
    event::{Event, Header, Payload},
};
use anyhow::Result;
use bpf_common::{program::BpfEvent, time::Timestamp, Pid};
use semver::Version;
use serde::{Deserialize, Serialize};
use tokio::sync::{
    broadcast::{self, error::RecvError},
    mpsc,
};
use validatron::{Primitive, ValidatronTypeProvider};

use super::{
    process_tracker::{ProcessInfo, ProcessTrackerHandle},
    CleanExit, ModuleContext, ShutdownSignal,
};

pub type PulsarModuleTask = dyn Future<Output = Result<CleanExit, ModuleError>> + Send;

type ModuleStartFn = dyn Fn(ModuleContext, ShutdownSignal) -> Box<PulsarModuleTask> + Send;

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
    pub fn new<N, F, Fut>(name: N, version: Version, task_start_fn: F) -> Self
    where
        N: Into<ModuleName>,
        F: Fn(ModuleContext, ShutdownSignal) -> Fut,
        F: Send + Sync + 'static,
        Fut: Future<Output = Result<CleanExit, ModuleError>>,
        Fut: Send + 'static,
    {
        Self {
            name: name.into(),
            info: ModuleDetails { version },
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

impl ValidatronTypeProvider for ModuleName {
    fn field_type() -> validatron::ValidatronType<Self> {
        validatron::ValidatronType::Primitive(Primitive {
            parse_fn: Box::new(|s| Ok(ModuleName(Cow::Owned(s.to_string())))),
            handle_op_fn: Box::new(|op| match op {
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
        })
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
    pub(crate) error_sender: ErrorSender,
}

/// Raises unrecoverable errors from the module to the upper layer.
///
/// Sending an error leads to a graceful shutdown of the module, the upper layer will stop the module via [`PulsarModuleTask::stop`].
pub(crate) type ErrorSender = mpsc::Sender<ModuleError>;
pub type ModuleError = Box<dyn std::error::Error + Send + Sync + 'static>;

impl ModuleSender {
    pub fn send(&self, process: Pid, timestamp: Timestamp, payload: Payload) {
        self.send_internal(process, timestamp, payload, false)
    }

    pub fn send_threat(&self, process: Pid, timestamp: Timestamp, payload: Payload) {
        self.send_internal(process, timestamp, payload, true)
    }

    /// Send a [`Payload`] to the [`Bus`].
    fn send_internal(&self, process: Pid, timestamp: Timestamp, payload: Payload, is_threat: bool) {
        let tx = self.tx.clone();
        let source = self.module_name.clone();
        let process_tracker = self.process_tracker.clone();
        let module_name = self.module_name.clone();
        tokio::spawn(async move {
            let mut header = Header {
                source,
                is_threat,
                pid: process.as_raw(),
                timestamp: timestamp.into(),
                image: String::new(),
                parent: 0,
                fork_time: UNIX_EPOCH,
            };
            match process_tracker.get(process, timestamp).await {
                Ok(ProcessInfo {
                    image,
                    ppid,
                    fork_time,
                    argv: _,
                }) => {
                    header.image = image;
                    header.parent = ppid.as_raw();
                    header.fork_time = fork_time.into();
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

    /// Send an event which was caused by another one.
    /// The new event shares the source headers, but has a new payload.
    pub fn send_derived_event(&self, source: &Event, payload: Payload) {
        let header = source.header.clone();
        let _ = self.tx.send(Event { header, payload });
    }

    pub fn raise_error(&self, err: ModuleError) {
        // We don't want to make raise_error async, so we use try_send and ignore
        // the error. Since errors are fatal, it's not a problem to lose one when
        // the buffer is full.
        let _ = self.error_sender.try_send(err);
    }
}

/// This allows to teat a ModuleSender as a bpf_common::Sender<T> for any T which
/// can be converted into a Payload. This allows probes to send Pulsar events despite
/// not knowing anything about Pulsar.
impl<T: Into<Payload> + fmt::Display> bpf_common::BpfSender<T> for ModuleSender {
    fn send(&mut self, data: Result<BpfEvent<T>, bpf_common::ProgramError>) {
        match data {
            Ok(data) => {
                ModuleSender::send(self, data.pid, data.timestamp, data.payload.into());
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
    pub async fn recv(&mut self) -> Result<Arc<Event>, BusError> {
        let mut lost: u64 = 0;
        loop {
            match broadcast::Receiver::recv(&mut self.rx).await {
                Ok(value) => {
                    if lost > 0 {
                        log::warn!(
                            target : &self.module_name,
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
}
