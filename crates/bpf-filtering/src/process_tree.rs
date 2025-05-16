use std::{
    io::{self, BufRead, BufReader},
    num::ParseIntError,
    str::{FromStr, SplitWhitespace},
    sync::{Arc, RwLock, Weak},
};

use bpf_common::{
    Gid, Pid, Uid,
    aya::{
        Btf, BtfError, Ebpf,
        programs::{Iter, ProgramError, links::LinkError},
    },
    containers::ContainerId,
};
use lazy_static::lazy_static;
use pulsar_core::event::{ContainerEngineKind, EventError, Namespaces};
use regex::Regex;
use thiserror::Error;

lazy_static! {
    static ref NAMESPACE_RE: Regex = Regex::new(r"(\d+)").unwrap();
}

pub(crate) struct TreeNode<T> {
    value: T,
    parent: Option<Weak<TreeNode<T>>>,
    children: RwLock<Vec<Arc<TreeNode<T>>>>,
}

impl<T> TreeNode<T> {
    pub(crate) fn new(value: T) -> Arc<Self> {
        Arc::new(Self {
            value,
            parent: None,
            children: RwLock::new(Vec::new()),
        })
    }

    pub(crate) fn add_child(self: &Arc<Self>, value: T) {
        let child_node = Arc::new(TreeNode {
            value,
            parent: Some(Arc::<Self>::downgrade(&self)),
            children: RwLock::new(Vec::new()),
        });
        self.children.write().unwrap().push(child_node);
    }

    pub(crate) fn iter(self: &Arc<Self>) -> TreeNodeDFSIter<T> {
        TreeNodeDFSIter {
            current: Some(Arc::clone(self)),
            stack: Vec::new(),
        }
    }

    pub(crate) fn parents(self: &Arc<Self>) -> TreeNodeParentIter<T> {
        TreeNodeParentIter {
            current: self.parent.as_ref().and_then(|weak| weak.upgrade()),
        }
    }
}

pub(crate) struct TreeNodeDFSIter<T> {
    current: Option<Arc<TreeNode<T>>>,
    stack: Vec<Arc<TreeNode<T>>>,
}

impl<T> Iterator for TreeNodeDFSIter<T> {
    type Item = Arc<TreeNode<T>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.current.take().map(|node| {
            {
                let children = node.children.read().unwrap();
                let mut children = children.iter();
                self.current = children.next().map(Arc::clone);
                self.stack.extend(children.map(Arc::clone));
            }
            node
        })
    }
}

pub(crate) struct TreeNodeParentIter<T> {
    current: Option<Arc<TreeNode<T>>>,
}

impl<T> Iterator for TreeNodeParentIter<T> {
    type Item = Arc<TreeNode<T>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.current.take().map(|node| {
            self.current = node.parent.as_ref().and_then(|w| w.upgrade());
            node
        })
    }
}

/// ProcessTree contains information about all running processes
pub(crate) struct ProcessTree {
    processes: Arc<TreeNode<ProcessData>>,
}

impl ProcessTree {
    pub(crate) fn push(&self, process: ProcessData) {
        let parent_node = self
            .processes
            .iter()
            .find(|p| p.value.pid == process.parent);
    }
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

/// Takes an element fron the BPF iterator program's output and parses the
/// given type `T` from it.
#[inline]
fn parse_bpf_iter_elem<T>(s: &str, parts: &mut SplitWhitespace) -> Result<T, Error>
where
    T: FromStr<Err = ParseIntError>,
{
    parts
        .next()
        .ok_or_else(|| Error::InvalidIteratorOutputFormat(s.to_owned()))?
        .parse()
        .map_err(Error::from)
}

impl FromStr for ProcessData {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split_whitespace();

        let pid: i32 = parse_bpf_iter_elem(s, &mut parts)?;
        let pid = Pid::from_raw(pid);
        let uid: u32 = parse_bpf_iter_elem(s, &mut parts)?;
        let uid = Uid::from_raw(uid);
        let gid: u32 = parse_bpf_iter_elem(s, &mut parts)?;
        let gid = Gid::from_raw(gid);
        let ppid: i32 = parse_bpf_iter_elem(s, &mut parts)?;
        let parent = Pid::from_raw(ppid);

        let uts: u32 = parse_bpf_iter_elem(s, &mut parts)?;
        let ipc: u32 = parse_bpf_iter_elem(s, &mut parts)?;
        let mnt: u32 = parse_bpf_iter_elem(s, &mut parts)?;
        let pid_ns: u32 = parse_bpf_iter_elem(s, &mut parts)?;
        let net: u32 = parse_bpf_iter_elem(s, &mut parts)?;
        let time: u32 = parse_bpf_iter_elem(s, &mut parts)?;
        let cgroup: u32 = parse_bpf_iter_elem(s, &mut parts)?;
        let namespaces = Namespaces {
            uts,
            ipc,
            mnt,
            pid: pid_ns,
            net,
            time,
            cgroup,
        };

        let image = parts
            .next()
            .ok_or_else(|| Error::InvalidIteratorOutputFormat(s.to_owned()))?
            .to_owned();

        let container_id = match (parts.next(), parts.next()) {
            (Some(container_engine), Some(container_id)) => {
                let container_engine: u32 = container_engine.parse()?;
                let container_engine = ContainerEngineKind::from_raw(container_engine)?;
                let container_id = container_id.to_owned();
                let container_id = match container_engine {
                    ContainerEngineKind::Docker => ContainerId::Docker(container_id),
                    ContainerEngineKind::Podman => ContainerId::Libpod(container_id),
                };
                Some(container_id)
            }
            (None, None) => None,
            _ => return Err(Error::InvalidIteratorOutputFormat(s.to_owned())),
        };

        Ok(Self {
            pid,
            uid,
            gid,
            image,
            parent,
            namespaces,
            container_id,
        })
    }
}

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("loading process {pid}: process not found")]
    ProcessNotFound { pid: Pid },
    #[error("loading process {pid}: parent image {ppid} not found")]
    ParentNotFound { pid: Pid, ppid: Pid },
    #[error("failed to parse BTF from sysfs")]
    Btf(#[source] BtfError),
    #[error("could not find the BPF iterator program")]
    ProgramNotFound,
    #[error("BPF iterator program has an invalid type")]
    InvalidProgramType(#[source] ProgramError),
    #[error("failed to load BPF iterator program")]
    ProgramLoad(#[source] ProgramError),
    #[error("failed to attach to BPF iterator program")]
    ProgramAttach(#[source] ProgramError),
    #[error("failed to take the link to the BPF iterator program")]
    ProgramLink(#[source] ProgramError),
    #[error("failed to open the link to the BPF iterator program")]
    ProgramLinkOpen(#[source] LinkError),
    #[error("failed to read the line from the BPF iterator")]
    LineRead(#[source] io::Error),
    #[error("invalid format of BPF iterator output, expected 12 or 14 elements, got `{0}`")]
    InvalidIteratorOutputFormat(String),
    #[error("failed to parse an integer: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
    #[error(transparent)]
    EventError(#[from] EventError),
}

pub(crate) const PID_0: Pid = Pid::from_raw(0);

impl ProcessTree {
    /// Creates a process tree based on the information returned by the BPF
    /// iterator program.
    pub(crate) fn load_from_bpf_iterator(bpf: &mut Ebpf) -> Result<Self, Error> {
        let btf = Btf::from_sys_fs().map_err(Error::Btf)?;
        let prog: &mut Iter = bpf
            .program_mut("iter_task")
            .ok_or_else(|| Error::ProgramNotFound)?
            .try_into()
            .map_err(Error::InvalidProgramType)?;
        prog.load("task", &btf).map_err(Error::ProgramLoad)?;

        let link_id = prog.attach().map_err(Error::ProgramAttach)?;
        let link = prog.take_link(link_id).map_err(Error::ProgramLink)?;
        let file = link.into_file().map_err(Error::ProgramLinkOpen)?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        let line = lines.next().unwrap().unwrap();
        let process = ProcessData::from_str(&line)?;

        let first_node = TreeNode::new(process);
        let mut last_node = Arc::clone(&first_node);

        for line in lines {
            let line = line.unwrap();
            let process = ProcessData::from_str(&line)?;
            let ppid = process.parent;

            if last_node.value.pid == ppid {
                last_node.add_child(process);
            } else {
                last_node = Arc::clone(&first_node);
            }
        }

        Ok(Self {
            processes: first_node,
        })
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
