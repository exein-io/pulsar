use std::io::{BufRead, BufReader};

use bpf_common::{
    aya::{programs::Iter, Btf, Ebpf},
    containers::ContainerId,
    Gid, Pid, Uid,
};
use lazy_static::lazy_static;
use pulsar_core::event::{ContainerEngineKind, Namespaces};
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
    pub(crate) uid: Uid,
    pub(crate) gid: Gid,
    pub(crate) image: String,
    pub(crate) parent: Pid,
    pub(crate) namespaces: Namespaces,
    pub(crate) container_id: Option<ContainerId>,
}

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("loading process {pid}: process not found")]
    ProcessNotFound { pid: Pid },
    #[error("loading process {pid}: parent image {ppid} not found")]
    ParentNotFound { pid: Pid, ppid: Pid },
}

pub(crate) const PID_0: Pid = Pid::from_raw(0);

impl ProcessTree {
    pub(crate) fn load_from_bpf_iterator(bpf: &mut Ebpf) -> Result<Self, Error> {
        let mut processes = Vec::new();

        let btf = Btf::from_sys_fs().unwrap();
        let prog: &mut Iter = bpf.program_mut("iter_task").unwrap().try_into().unwrap();
        prog.load("task", &btf).unwrap();

        let link_id = prog.attach().unwrap();
        let link = prog.take_link(link_id).unwrap();
        let file = link.into_file().unwrap();
        let reader = BufReader::new(file);

        let lines = reader.lines();
        for line in lines {
            let line = line.unwrap();
            let parts: Vec<_> = line.split_whitespace().collect();

            if parts.len() != 12 || parts.len() != 14 {
                panic!("invalid format");
            }

            let pid: i32 = parts[0].parse().unwrap();
            let pid = Pid::from_raw(pid);
            let uid: u32 = parts[1].parse().unwrap();
            let uid = Uid::from_raw(uid);
            let gid: u32 = parts[2].parse().unwrap();
            let gid = Gid::from_raw(gid);
            let ppid: i32 = parts[3].parse().unwrap();
            let parent = Pid::from_raw(ppid);

            let uts: u32 = parts[4].parse().unwrap();
            let ipc: u32 = parts[5].parse().unwrap();
            let mnt: u32 = parts[6].parse().unwrap();
            let pid_ns: u32 = parts[7].parse().unwrap();
            let net: u32 = parts[8].parse().unwrap();
            let time: u32 = parts[9].parse().unwrap();
            let cgroup: u32 = parts[10].parse().unwrap();
            let namespaces = Namespaces {
                uts,
                ipc,
                mnt,
                pid: pid_ns,
                net,
                time,
                cgroup,
            };

            let is_a_container: u32 = parts[11].parse().unwrap();
            let container_id = if is_a_container == 1 {
                let container_engine: u32 = parts[12].parse().unwrap();
                let container_engine = match container_engine {
                    0 => ContainerEngineKind::Docker,
                    1 => ContainerEngineKind::Podman,
                    _ => panic!("unknown container engine"),
                };
                let container_id = parts[13].to_owned();
                let container_id = match container_engine {
                    ContainerEngineKind::Docker => ContainerId::Docker(container_id),
                    ContainerEngineKind::Podman => ContainerId::Libpod(container_id),
                };
                Some(container_id)
            } else {
                None
            };

            let process = ProcessData {
                pid,
                uid,
                gid,
                image: String::new(),
                parent,
                namespaces,
                container_id,
            };

            processes.push(process);
        }

        Ok(Self { processes })
    }

    /// Add a new entry and return its process info.
    /// This is needed during initialization to go from raw fork/exec events to
    /// the full PorcessData needed by the policy filtering setup.
    pub(crate) fn fork(
        &mut self,
        pid: Pid,
        ppid: Pid,
        uid: Uid,
        gid: Gid,
        namespaces: Namespaces,
        container_id: Option<ContainerId>,
    ) -> Result<&ProcessData, Error> {
        let parent = self.processes.iter().find(|p| p.pid == ppid);
        match parent {
            Some(parent) => {
                let image = parent.image.to_string();

                self.processes.push(ProcessData {
                    pid,
                    uid,
                    gid,
                    image,
                    parent: ppid,
                    namespaces,
                    container_id,
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
