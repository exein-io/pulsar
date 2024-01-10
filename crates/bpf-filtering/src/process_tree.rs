use std::{collections::HashMap, fs, path::Path};

use bpf_common::{
    parsing::procfs::{self, ProcfsError},
    Pid,
};
use lazy_static::lazy_static;
use pulsar_core::event::Namespaces;
use regex::Regex;
use thiserror::Error;

lazy_static! {
    static ref NAMESPACE_RE: Regex = Regex::new(r"(\d+)").unwrap();
}

/// ProcessTree contains information about all running processes
pub(crate) struct ProcessTree {
    processes: Vec<ProcessData>,
}

#[derive(Debug)]
pub(crate) struct ProcessData {
    pub(crate) pid: Pid,
    pub(crate) image: String,
    pub(crate) parent: Pid,
    pub(crate) namespaces: Namespaces,
}

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("loading process {pid}: process not found")]
    ProcessNotFound { pid: Pid },
    #[error("loading process {pid}: parent image {ppid} not found")]
    ParentNotFound { pid: Pid, ppid: Pid },
    #[error(transparent)]
    Procfs(#[from] ProcfsError),
    #[error("failed to get the {ns_type} namespace for process {pid}")]
    Namespace { pid: Pid, ns_type: String },
}

pub(crate) const PID_0: Pid = Pid::from_raw(0);

fn get_process_namespace(pid: Pid, ns_type: &str) -> Result<u32, Error> {
    let path = Path::new("/proc")
        .join(pid.to_string())
        .join("ns")
        .join(ns_type);

    let link_target = fs::read_link(path).map_err(|_| Error::Namespace {
        pid,
        ns_type: ns_type.to_owned(),
    })?;
    let link_target = link_target.to_string_lossy();
    let ns: u32 = NAMESPACE_RE
        .captures(&link_target)
        .and_then(|cap| cap.get(1))
        .and_then(|m| m.as_str().parse().ok())
        .ok_or(Error::Namespace {
            pid,
            ns_type: ns_type.to_owned(),
        })?;

    Ok(ns)
}

fn get_process_namespace_or_log(pid: Pid, namespace_type: &str) -> u32 {
    get_process_namespace(pid, namespace_type).map_or_else(
        |e| {
            if pid.as_raw() != 0 {
                log::warn!(
                    "Failed to determine {} namespace for process {:?}: {}",
                    namespace_type,
                    pid,
                    e
                );
            }
            u32::default()
        },
        |v| v,
    )
}

fn get_process_namespaces(pid: Pid) -> Namespaces {
    Namespaces {
        uts: get_process_namespace_or_log(pid, "uts"),
        ipc: get_process_namespace_or_log(pid, "ipc"),
        mnt: get_process_namespace_or_log(pid, "mnt"),
        net: get_process_namespace_or_log(pid, "net"),
        pid: get_process_namespace_or_log(pid, "pid"),
        time: get_process_namespace_or_log(pid, "time"),
        cgroup: get_process_namespace_or_log(pid, "cgroup"),
    }
}

impl ProcessTree {
    /// Construct the `ProcessTree` by reading from `procfs`:
    /// - process list
    /// - parent pid
    /// - image
    pub(crate) fn load_from_procfs() -> Result<Self, Error> {
        let mut processes: HashMap<Pid, ProcessData> = HashMap::new();
        let mut children: HashMap<Pid, Vec<Pid>> = HashMap::new();
        let mut sorted_processes: Vec<ProcessData> = Vec::new();

        // Get process list
        for pid in procfs::get_running_processes()? {
            let image = procfs::get_process_image(pid)
                .map(|path| path.to_string_lossy().to_string())
                .unwrap_or_else(|err| {
                    log::debug!("{}", err);
                    String::new()
                });
            let parent = procfs::get_process_parent_pid(pid).unwrap_or_else(|err| {
                log::debug!("Error getting parent pid of {pid}: {}", err);
                Pid::from_raw(1)
            });
            let namespaces = get_process_namespaces(pid);
            processes.insert(
                pid,
                ProcessData {
                    pid,
                    image,
                    parent,
                    namespaces,
                },
            );
            children.entry(parent).or_default().push(pid);
        }

        // Make sure to add PID 0 (which is part of kernel) to map_interest to avoid
        // warnings about missing entries.
        let namespaces = get_process_namespaces(PID_0);
        processes.insert(
            PID_0,
            ProcessData {
                pid: PID_0,
                image: String::from("kernel"),
                parent: PID_0,
                namespaces,
            },
        );

        // Sort process tree by starting by process 0
        fn add_process_and_children(
            pid: Pid,
            processes: &mut HashMap<Pid, ProcessData>,
            children: &mut HashMap<Pid, Vec<Pid>>,
            sorted_processes: &mut Vec<ProcessData>,
        ) {
            let process = processes.remove(&pid).unwrap();
            sorted_processes.push(process);
            for child in children.remove(&pid).unwrap_or_default() {
                add_process_and_children(child, processes, children, sorted_processes);
            }
        }
        add_process_and_children(PID_0, &mut processes, &mut children, &mut sorted_processes);
        if !processes.is_empty() {
            log::warn!("Found processes not starting from root: {:?}", processes);
            sorted_processes.extend(processes.into_values());
        }

        Ok(Self {
            processes: sorted_processes,
        })
    }

    /// Add a new entry and return its process info.
    /// This is needed during initialization to go from raw fork/exec events to
    /// the full PorcessData needed by the policy filtering setup.
    pub(crate) fn fork(&mut self, pid: Pid, ppid: Pid) -> Result<&ProcessData, Error> {
        let parent = self.processes.iter().find(|p| p.pid == ppid);
        match parent {
            Some(parent) => {
                let image = parent.image.to_string();
                let namespaces = get_process_namespaces(pid);
                self.processes.push(ProcessData {
                    pid,
                    image,
                    parent: ppid,
                    namespaces,
                });
                Ok(self.processes.last().unwrap())
            }
            None => Err(Error::ParentNotFound { pid, ppid }),
        }
    }

    pub(crate) fn exec(&mut self, pid: Pid, image: &str) -> Result<&ProcessData, Error> {
        match self.processes.iter().position(|p| p.pid == pid) {
            Some(i) => {
                self.processes[i].image = image.to_string();
                Ok(&self.processes[i])
            }
            None => Err(Error::ProcessNotFound { pid }),
        }
    }
}

impl<'a> IntoIterator for &'a ProcessTree {
    type Item = &'a ProcessData;
    type IntoIter = std::slice::Iter<'a, ProcessData>;
    fn into_iter(self) -> Self::IntoIter {
        self.processes.iter()
    }
}
