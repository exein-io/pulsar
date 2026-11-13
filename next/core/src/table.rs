//! The process table: what the processor knows about each process.
//!
//! Only the processor writes it, from lifecycle records, in stream order.
//! Every answer is checked against the identity and the exec id of the record
//! that asks: a process the table can't vouch for is unknown, never guessed.
//!
//! Under review: the per-process event windows and the lineage (with
//! [`Ancestor`], [`ProcessSnapshot`] and `is_descendant_of`) go beyond OSS
//! Pulsar's process tracker; only EE has them today. They may be removed.
//! What the header needs (`apply`, `enrich`, `seed`) stays: OSS rules read it.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use crate::{
    event::{Container, Event, Header, ProcessId, Subject},
    payload::{Argv, Text},
    seed::SeedProcess,
    threat::{Ancestor, ProcessSnapshot},
    time::boot_to_system,
};

#[derive(Clone, Debug)]
pub struct TableConfig {
    /// Events remembered per process. Under review, see the module docs.
    pub window: usize,
    /// Ancestors in a lineage. Under review, see the module docs.
    pub lineage_depth: usize,
    /// How long an exited process stays, for records that arrive after its
    /// exit (boot-clock nanoseconds).
    pub retire_after: u64,
}

impl Default for TableConfig {
    fn default() -> Self {
        Self {
            window: 16,
            lineage_depth: 8,
            retire_after: 5_000_000_000,
        }
    }
}

/// Whether a process runs in a container.
#[derive(Clone, Debug)]
pub enum Membership {
    Host,
    Container(Container),
}

/// What a lifecycle record changes. `None` means the probe couldn't read it.
#[derive(Clone, Debug)]
pub enum Lifecycle {
    /// The record's subject is the child.
    Fork {
        membership: Option<Membership>,
    },
    Exec {
        image: Option<Text>,
        argv: Option<Argv>,
        membership: Option<Membership>,
    },
    Exit,
    ChangeParent {
        ppid: u32,
    },
    CredsChange {
        uid: u32,
        gid: u32,
    },
}

/// A process as it was when it forked a child: kept by the child, so a lineage
/// outlives the ancestors in it. Under review, see the module docs.
struct Frozen<P> {
    process: ProcessSnapshot,
    window: Vec<Arc<Event<P>>>,
    window_spans_gap: bool,
    up: Option<Arc<Frozen<P>>>,
}

struct Node<P> {
    id: ProcessId,
    /// False for processes read from /proc, whose start time is only known
    /// to the clock tick.
    exact_start: bool,
    ppid: u32,
    parent: Option<ProcessId>,
    /// The exec id `image` and `argv` belong to.
    exec_id: Option<u64>,
    image: Option<Text>,
    argv: Option<Argv>,
    membership: Option<Membership>,
    uid: Option<u32>,
    gid: Option<u32>,
    /// Recent events, each with the loss counter when it was added. Under
    /// review, see the module docs.
    window: VecDeque<(u64, Arc<Event<P>>)>,
    /// Under review, see the module docs.
    forked_from: Option<Arc<Frozen<P>>>,
    exited: bool,
}

impl<P> Node<P> {
    fn new(id: ProcessId, ppid: u32, parent: Option<ProcessId>) -> Self {
        Self {
            id,
            exact_start: true,
            ppid,
            parent,
            exec_id: None,
            image: None,
            argv: None,
            membership: None,
            uid: None,
            gid: None,
            window: VecDeque::new(),
            forked_from: None,
            exited: false,
        }
    }
}

pub struct ProcessTable<P> {
    config: TableConfig,
    nodes: HashMap<u32, Node<P>>,
    /// Container membership learned from fork and exec records, by cgroup id:
    /// it also covers processes whose own fork and exec were lost.
    cgroups: HashMap<u64, Membership>,
    /// Records lost so far.
    lost: u64,
    retiring: VecDeque<(u64, ProcessId)>,
    tick_ns: u64,
}

impl<P> ProcessTable<P> {
    pub fn new(config: TableConfig) -> Self {
        Self {
            config,
            nodes: HashMap::new(),
            cgroups: HashMap::new(),
            lost: 0,
            retiring: VecDeque::new(),
            tick_ns: crate::seed::tick_ns(),
        }
    }

    /// Records were lost at this position of the stream.
    pub fn note_loss(&mut self, records: u32) {
        self.lost += u64::from(records);
    }

    /// Applies a lifecycle record. Runs before the same record is enriched.
    pub fn apply(&mut self, subject: &Subject, timestamp: u64, lifecycle: &Lifecycle) {
        self.retire(timestamp);
        match lifecycle {
            Lifecycle::Fork { membership } => {
                self.learn(subject.cgroup_id, membership);
                let parent = self.live(subject.ppid).map(|parent| parent.id);
                let mut node = Node::new(subject.id(), subject.ppid, parent);
                if let Some(parent) = parent.and_then(|parent| self.lookup(parent)) {
                    // A fork copies the exec id, so the parent's image is the
                    // child's only if the table knows the parent's current exec.
                    if parent.exec_id == Some(subject.exec_id) {
                        node.image = parent.image.clone();
                        node.argv = parent.argv.clone();
                    }
                }
                node.exec_id = Some(subject.exec_id);
                node.membership = membership.clone();
                node.uid = Some(subject.uid);
                node.gid = Some(subject.gid);
                node.forked_from = self.frozen(parent, self.config.lineage_depth);
                self.nodes.insert(subject.pid, node);
            }
            Lifecycle::Exec {
                image,
                argv,
                membership,
            } => {
                self.learn(subject.cgroup_id, membership);
                let node = self.node_for(subject);
                node.exec_id = Some(subject.exec_id);
                node.image = image.clone();
                node.argv = argv.clone();
                if membership.is_some() {
                    node.membership = membership.clone();
                }
            }
            Lifecycle::Exit => {
                let deadline = timestamp + self.config.retire_after;
                self.node_for(subject).exited = true;
                self.retiring.push_back((deadline, subject.id()));
            }
            Lifecycle::ChangeParent { ppid } => {
                let parent = self.live(*ppid).map(|parent| parent.id);
                let node = self.node_for(subject);
                node.ppid = *ppid;
                node.parent = parent;
            }
            Lifecycle::CredsChange { uid, gid } => {
                let node = self.node_for(subject);
                node.uid = Some(*uid);
                node.gid = Some(*gid);
            }
        }
    }

    /// Fills the header fields that come from the table.
    pub fn enrich(&mut self, header: &mut Header) {
        let Some(subject) = &header.subject else {
            return;
        };
        let learned = self.cgroups.get(&subject.cgroup_id).cloned();
        let node = self.node_for(subject);
        // A process read from /proc has an image but no exec id yet: bind it
        // to the first one seen.
        if node.exec_id.is_none() && node.image.is_some() {
            node.exec_id = Some(subject.exec_id);
        }
        header.image = if node.exec_id == Some(subject.exec_id) {
            node.image.clone()
        } else {
            None
        };
        header.container = match node.membership.clone().or(learned) {
            Some(Membership::Container(container)) => Some(container),
            Some(Membership::Host) | None => None,
        };
        header.fork_time = Some(boot_to_system(subject.start_time));
    }

    /// Adds an event to its process's window. Under review, see the module
    /// docs.
    pub fn remember(&mut self, event: &Arc<Event<P>>) {
        let Some(subject) = &event.header.subject else {
            return;
        };
        let (lost, window) = (self.lost, self.config.window);
        let node = self.node_for(subject);
        if node.window.len() == window {
            node.window.pop_front();
        }
        node.window.push_back((lost, event.clone()));
    }

    /// Adds processes read from /proc, in parent-first order. Processes the
    /// stream already told about are left alone.
    pub fn seed(&mut self, processes: Vec<SeedProcess>) {
        for process in processes {
            if self.nodes.contains_key(&process.pid) {
                continue;
            }
            let id = ProcessId {
                pid: process.pid,
                start_time: process.start_ticks * self.tick_ns,
            };
            let parent = self.live(process.ppid).map(|parent| parent.id);
            let mut node = Node::new(id, process.ppid, parent);
            node.exact_start = false;
            node.image = process.image.map(|image| Text {
                value: image,
                truncated: false,
            });
            node.membership = process.membership;
            node.uid = Some(process.uid);
            node.gid = Some(process.gid);
            self.nodes.insert(process.pid, node);
        }
    }

    /// Under review, see the module docs.
    pub fn snapshot(&self, id: ProcessId) -> ProcessSnapshot {
        self.lookup(id)
            .map(|node| self.snapshot_of(node))
            .unwrap_or_default()
    }

    /// The process's recent events, and whether records were lost among them.
    /// Under review, see the module docs.
    pub fn window(&self, id: ProcessId) -> Option<(Vec<Arc<Event<P>>>, bool)> {
        self.lookup(id).map(|node| {
            let events = node.window.iter().map(|(_, event)| event.clone()).collect();
            (events, self.spans_gap(node))
        })
    }

    /// The ancestors of `id`, nearest first. Ancestors past a lost record are
    /// `Unknown`. Under review, see the module docs.
    pub fn lineage(&self, id: ProcessId) -> Vec<Ancestor<P>> {
        let depth = self.config.lineage_depth;
        let Some(node) = self.lookup(id) else {
            return Vec::new();
        };
        let mut lineage = Vec::new();
        let mut next = match &node.forked_from {
            Some(frozen) => Some(frozen.clone()),
            // The fork was lost or happened before start: take the parent as
            // it is now.
            None => self.frozen(node.parent, depth),
        };
        let mut last_ppid = Some(node.ppid);
        while let Some(frozen) = next {
            if lineage.len() == depth {
                return lineage;
            }
            lineage.push(Ancestor::Known {
                process: frozen.process.clone(),
                window: frozen.window.clone(),
                window_spans_gap: frozen.window_spans_gap,
            });
            last_ppid = frozen.process.ppid;
            next = frozen.up.clone();
        }
        if lineage.len() < depth && last_ppid.is_some_and(|ppid| ppid != 0) {
            lineage.push(Ancestor::Unknown { pid: last_ppid });
        }
        lineage
    }

    /// Whether an ancestor of `id` runs `image`. Under review, see the module
    /// docs.
    pub fn is_descendant_of(&self, id: ProcessId, image: &str) -> bool {
        self.lineage(id).iter().any(|ancestor| {
            matches!(ancestor, Ancestor::Known { process, .. }
                if process.image.as_ref().is_some_and(|known| known.value == image))
        })
    }

    fn lookup(&self, id: ProcessId) -> Option<&Node<P>> {
        self.nodes
            .get(&id.pid)
            .filter(|node| self.same_start(node, id.start_time))
    }

    /// The current process with this pid, whichever it is.
    fn live(&self, pid: u32) -> Option<&Node<P>> {
        self.nodes.get(&pid).filter(|node| !node.exited)
    }

    fn same_start(&self, node: &Node<P>, start_time: u64) -> bool {
        if node.exact_start {
            node.id.start_time == start_time
        } else {
            node.id.start_time / self.tick_ns == start_time / self.tick_ns
        }
    }

    /// The node of the record's subject. A process the table doesn't know, or
    /// knows under an older start time (pid reuse), gets a new node with only
    /// what the record says.
    fn node_for(&mut self, subject: &Subject) -> &mut Node<P> {
        let id = subject.id();
        let known = self
            .nodes
            .get(&id.pid)
            .is_some_and(|node| self.same_start(node, id.start_time));
        if !known {
            let parent = self.live(subject.ppid).map(|parent| parent.id);
            let mut node = Node::new(id, subject.ppid, parent);
            node.uid = Some(subject.uid);
            node.gid = Some(subject.gid);
            self.nodes.insert(id.pid, node);
        }
        let node = self.nodes.get_mut(&id.pid).expect("inserted above");
        if !node.exact_start {
            node.id.start_time = id.start_time;
            node.exact_start = true;
        }
        node
    }

    /// `id` as it is now, with its own ancestors, as a child would keep it.
    fn frozen(&self, id: Option<ProcessId>, depth: usize) -> Option<Arc<Frozen<P>>> {
        if depth == 0 {
            return None;
        }
        let node = self.lookup(id?)?;
        Some(Arc::new(Frozen {
            process: self.snapshot_of(node),
            window: node.window.iter().map(|(_, event)| event.clone()).collect(),
            window_spans_gap: self.spans_gap(node),
            up: match &node.forked_from {
                Some(frozen) => Some(frozen.clone()),
                None => self.frozen(node.parent, depth - 1),
            },
        }))
    }

    fn spans_gap(&self, node: &Node<P>) -> bool {
        node.window
            .front()
            .is_some_and(|(lost, _)| *lost < self.lost)
    }

    fn snapshot_of(&self, node: &Node<P>) -> ProcessSnapshot {
        ProcessSnapshot {
            pid: Some(node.id.pid),
            start_time: Some(boot_to_system(node.id.start_time)),
            ppid: Some(node.ppid),
            uid: node.uid,
            gid: node.gid,
            image: node.image.clone(),
            argv: node.argv.clone(),
            container: match &node.membership {
                Some(Membership::Container(container)) => Some(container.clone()),
                _ => None,
            },
            exited: node.exited,
        }
    }

    fn learn(&mut self, cgroup_id: u64, membership: &Option<Membership>) {
        if let Some(membership) = membership {
            self.cgroups.insert(cgroup_id, membership.clone());
        }
    }

    fn retire(&mut self, now: u64) {
        while let Some(&(deadline, id)) = self.retiring.front() {
            if deadline > now {
                break;
            }
            self.retiring.pop_front();
            if self
                .nodes
                .get(&id.pid)
                .is_some_and(|node| node.exited && node.id == id)
            {
                self.nodes.remove(&id.pid);
            }
        }
    }
}
