//! The process producer, `probes/process.bpf.c`.

use std::mem::offset_of;

use bpf_features::BpfFeatures;

use crate::{
    abi::{
        PULSAR_CONTAINER_DOCKER, PULSAR_CONTAINER_NONE, PULSAR_CONTAINER_PODMAN,
        PULSAR_PROCESS_CHANGE_PARENT, PULSAR_PROCESS_CREDS_CHANGE, PULSAR_PROCESS_EXEC,
        PULSAR_PROCESS_EXIT, PULSAR_PROCESS_FORK, PULSAR_PROCESS_MISSING_CONTAINER,
        PULSAR_PROCESS_MISSING_NAMESPACES, pulsar_container, pulsar_namespaces,
        pulsar_process_change_parent, pulsar_process_creds_change, pulsar_process_exec,
        pulsar_process_exec_record, pulsar_process_exit, pulsar_process_fork,
    },
    loader::{Attach, ProbeSpec},
    objects,
    record::{DecodeError, Field, RecordView, tail_offset},
};

pub static SPEC: ProbeSpec = ProbeSpec {
    name: "process",
    objects: objects::PROCESS,
    programs,
};

fn programs(features: &BpfFeatures) -> Vec<Attach> {
    let mut programs = vec![
        Attach::RawTracePoint("sched_process_fork"),
        Attach::RawTracePoint("sched_process_exec"),
        Attach::RawTracePoint("sched_process_exit"),
        Attach::RawTracePoint("sched_switch"),
    ];
    // The task_fix_set* hooks exist since 5.10, the oldest supported kernel,
    // so the probe's commit_creds fallback is never attached.
    if features.lsm {
        programs.extend([
            Attach::Lsm("task_fix_setuid"),
            Attach::Lsm("task_fix_setgid"),
        ]);
    } else {
        programs.extend([
            Attach::Kprobe("security_task_fix_setuid"),
            Attach::Kprobe("security_task_fix_setgid"),
        ]);
    }
    programs
}

const _: () =
    assert!(tail_offset::<pulsar_process_exec>() == offset_of!(pulsar_process_exec_record, tail));

pub type Namespaces = pulsar_namespaces;

/// The container of a process, as the probe found it.
#[derive(Clone, Debug)]
pub enum Container {
    /// Not in a container.
    Host,
    Docker(String),
    Podman(String),
}

/// A process record. `None` means the probe couldn't read the value.
#[derive(Debug)]
pub enum ProcessRecord<'a> {
    /// The subject is the child.
    Fork {
        namespaces: Option<Namespaces>,
        container: Option<Container>,
    },
    Exec {
        argc: u32,
        filename: Option<Field<'a>>,
        /// NUL-separated, see [`Field::split_nul`].
        argv: Option<Field<'a>>,
        namespaces: Option<Namespaces>,
        container: Option<Container>,
    },
    Exit {
        exit_code: u32,
    },
    /// The subject is the orphan.
    ChangeParent {
        ppid: u32,
    },
    /// The new credentials; the subject still has the old ones.
    CredsChange {
        uid: u32,
        gid: u32,
    },
}

pub fn decode<'a>(view: &RecordView<'a>) -> Result<ProcessRecord<'a>, DecodeError> {
    Ok(match view.kind() {
        PULSAR_PROCESS_FORK => {
            let body: pulsar_process_fork = view.body()?;
            ProcessRecord::Fork {
                namespaces: namespaces(body.missing, body.namespaces),
                container: container(body.missing, &body.container),
            }
        }
        PULSAR_PROCESS_EXEC => {
            let (body, tail) = view.body_and_tail::<pulsar_process_exec>()?;
            ProcessRecord::Exec {
                argc: body.argc,
                filename: tail.field(&body.filename)?,
                argv: tail.field(&body.argv)?,
                namespaces: namespaces(body.missing, body.namespaces),
                container: container(body.missing, &body.container),
            }
        }
        PULSAR_PROCESS_EXIT => {
            let body: pulsar_process_exit = view.body()?;
            ProcessRecord::Exit {
                exit_code: body.exit_code,
            }
        }
        PULSAR_PROCESS_CHANGE_PARENT => {
            let body: pulsar_process_change_parent = view.body()?;
            ProcessRecord::ChangeParent { ppid: body.ppid }
        }
        PULSAR_PROCESS_CREDS_CHANGE => {
            let body: pulsar_process_creds_change = view.body()?;
            ProcessRecord::CredsChange {
                uid: body.uid,
                gid: body.gid,
            }
        }
        _ => {
            return Err(DecodeError::UnknownKind {
                producer: view.producer(),
                kind: view.kind(),
            });
        }
    })
}

fn namespaces(missing: u32, namespaces: pulsar_namespaces) -> Option<Namespaces> {
    (missing & PULSAR_PROCESS_MISSING_NAMESPACES == 0).then_some(namespaces)
}

fn container(missing: u32, container: &pulsar_container) -> Option<Container> {
    if missing & PULSAR_PROCESS_MISSING_CONTAINER != 0 {
        return None;
    }
    let id = || {
        let id = container.name.get(container.id_offset as usize..)?;
        let end = id.iter().position(|byte| *byte == 0).unwrap_or(id.len());
        Some(String::from_utf8_lossy(&id[..end]).into_owned())
    };
    match container.engine {
        PULSAR_CONTAINER_NONE => Some(Container::Host),
        PULSAR_CONTAINER_DOCKER => id().map(Container::Docker),
        PULSAR_CONTAINER_PODMAN => id().map(Container::Podman),
        _ => None,
    }
}
