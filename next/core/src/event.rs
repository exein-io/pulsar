//! What detectors and rules see: a header and a payload.

use std::{fmt, time::SystemTime};

use next_bpf::abi::pulsar_subject;
use serde::Serialize;
use validatron::{Validatron, ValidatronClass};

use crate::payload::Text;

/// A process, unique across pid reuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct ProcessId {
    pub pid: u32,
    /// Boot-clock nanoseconds.
    pub start_time: u64,
}

/// The process a record is about, as the kernel saw it when writing it.
#[derive(Clone, Debug, Serialize, Validatron)]
pub struct Subject {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    /// Boot-clock nanoseconds.
    pub start_time: u64,
    /// Incremented by every exec of the process.
    pub exec_id: u64,
    pub cgroup_id: u64,
}

impl Subject {
    pub fn id(&self) -> ProcessId {
        ProcessId {
            pid: self.pid,
            start_time: self.start_time,
        }
    }
}

impl From<&pulsar_subject> for Subject {
    fn from(subject: &pulsar_subject) -> Self {
        Self {
            pid: subject.tgid,
            ppid: subject.ppid,
            uid: subject.uid,
            gid: subject.gid,
            start_time: subject.start_time,
            exec_id: subject.exec_id,
            cgroup_id: subject.cgroup_id,
        }
    }
}

#[derive(Clone, Debug, Serialize, Validatron)]
pub struct Container {
    /// "docker" or "podman".
    pub engine: String,
    pub id: String,
}

/// Every field that depends on other records is an `Option`: `None` means
/// unknown, never a default.
#[derive(Clone, Debug, Serialize, Validatron)]
pub struct Header {
    #[validatron(skip)]
    pub timestamp: SystemTime,
    /// The probe that wrote the record.
    #[validatron(skip)]
    pub source: &'static str,
    /// From the record. `None` only for records the probe couldn't attribute.
    pub subject: Option<Subject>,
    /// From the process table: `None` when the exec that set it was lost.
    pub image: Option<Text>,
    /// From the process table: `None` outside containers and when unknown.
    pub container: Option<Container>,
    #[validatron(skip)]
    pub fork_time: Option<SystemTime>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Event<P> {
    pub header: Header,
    pub payload: P,
}

impl<P: Validatron + Send + Sync + 'static> Validatron for Event<P> {
    fn get_class() -> ValidatronClass {
        Self::class_builder()
            .struct_class_builder()
            .add_field("header", Box::new(|event| &event.header))
            .add_field("payload", Box::new(|event| &event.payload))
            .build()
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.image {
            Some(image) => write!(f, "{image}")?,
            None => write!(f, "?")?,
        }
        match &self.subject {
            Some(subject) => write!(f, " ({})", subject.pid)?,
            None => write!(f, " (unattributed)")?,
        }
        if let Some(container) = &self.container {
            write!(f, " in {} {}", container.engine, container.id)?;
        }
        Ok(())
    }
}
