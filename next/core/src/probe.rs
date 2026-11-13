//! Probes: a kernel object and the decoder of its records.

use next_bpf::{
    loader::ProbeSpec,
    process::{self, ProcessRecord},
    record::{DecodeError, Field, RecordView},
};

use crate::{
    Schema,
    event::Container,
    payload::{Argv, OssPayload, Text},
    table::{Lifecycle, Membership},
};

/// A kernel producer: its object and how to turn its records into payloads.
pub trait Probe<S: Schema>: Send + 'static {
    fn spec(&self) -> &'static ProbeSpec;

    /// Whether the probe reports the process lifecycle. Such probes are
    /// attached before /proc is read, every other probe after.
    fn reports_lifecycle(&self) -> bool {
        false
    }

    /// Second decoding step: `next_bpf` checked the record and its producer
    /// module decodes the C layout; this maps the result to payloads.
    fn decode(
        &self,
        record: &RecordView<'_>,
        out: &mut Decoded<S::Payload>,
    ) -> Result<(), DecodeError>;
}

/// What one record decodes to.
pub struct Decoded<P> {
    /// Usually one; a record can carry more than one event.
    pub payloads: Vec<P>,
    /// Set by lifecycle records, for the process table.
    pub lifecycle: Option<Lifecycle>,
}

impl<P> Default for Decoded<P> {
    fn default() -> Self {
        Self {
            payloads: Vec::new(),
            lifecycle: None,
        }
    }
}

impl<P> Decoded<P> {
    pub fn clear(&mut self) {
        self.payloads.clear();
        self.lifecycle = None;
    }
}

/// `probes/process.bpf.c`.
pub struct ProcessProbe;

impl<S: Schema> Probe<S> for ProcessProbe {
    fn spec(&self) -> &'static ProbeSpec {
        &process::SPEC
    }

    fn reports_lifecycle(&self) -> bool {
        true
    }

    fn decode(
        &self,
        record: &RecordView<'_>,
        out: &mut Decoded<S::Payload>,
    ) -> Result<(), DecodeError> {
        // Process records are always attributed.
        let Some(subject) = record.subject() else {
            return Ok(());
        };
        let (payload, lifecycle) = match process::decode(record)? {
            ProcessRecord::Fork { container, .. } => (
                OssPayload::Fork {
                    ppid: subject.ppid,
                    uid: subject.uid,
                    gid: subject.gid,
                },
                Lifecycle::Fork {
                    membership: container.map(membership),
                },
            ),
            ProcessRecord::Exec {
                argc,
                filename,
                argv,
                container,
                ..
            } => {
                let filename = filename.map(text);
                let argv = argv.map(|argv| Argv {
                    args: argv.split_nul().map(String::from).collect(),
                    truncated: argv.truncated,
                });
                (
                    OssPayload::Exec {
                        filename: filename.clone(),
                        argc: argc as usize,
                        argv: argv.clone(),
                    },
                    Lifecycle::Exec {
                        image: filename,
                        argv,
                        membership: container.map(membership),
                    },
                )
            }
            ProcessRecord::Exit { exit_code } => (OssPayload::Exit { exit_code }, Lifecycle::Exit),
            ProcessRecord::ChangeParent { ppid } => (
                OssPayload::ChangeParent { ppid },
                Lifecycle::ChangeParent { ppid },
            ),
            ProcessRecord::CredsChange { uid, gid } => (
                OssPayload::CredentialsChange { uid, gid },
                Lifecycle::CredsChange { uid, gid },
            ),
        };
        out.payloads.push(payload.into());
        out.lifecycle = Some(lifecycle);
        Ok(())
    }
}

fn text(field: Field<'_>) -> Text {
    Text {
        value: field.to_string_lossy().into_owned(),
        truncated: field.truncated,
    }
}

fn membership(container: process::Container) -> Membership {
    match container {
        process::Container::Host => Membership::Host,
        process::Container::Docker(id) => Membership::Container(Container {
            engine: "docker".to_string(),
            id,
        }),
        process::Container::Podman(id) => Membership::Container(Container {
            engine: "podman".to_string(),
            id,
        }),
    }
}
