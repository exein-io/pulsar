//! The processes that were running before the probes were attached, read
//! from /proc.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
};

use anyhow::Context;
use aya::{Ebpf, maps::HashMap as BpfHashMap};
use bpf_common::{
    Pid,
    containers::ContainerId,
    parsing::procfs::{self, ProcfsError},
};
use bpf_filtering::{config::Config as FilteringConfig, maps::PolicyDecision};
use nix::unistd::{SysconfVar, sysconf};

use crate::{event::Container, table::Membership};

pub struct SeedProcess {
    pub pid: u32,
    pub ppid: u32,
    /// `starttime` of /proc/<pid>/stat: clock ticks since boot.
    pub start_ticks: u64,
    pub uid: u32,
    pub gid: u32,
    pub image: Option<String>,
    pub membership: Option<Membership>,
}

/// Nanoseconds per clock tick of /proc (USER_HZ).
pub fn tick_ns() -> u64 {
    let hz = sysconf(SysconfVar::CLK_TCK).ok().flatten().unwrap_or(100);
    1_000_000_000 / hz as u64
}

/// Every process in /proc, parents before their children. Processes that
/// exit while being read are skipped.
pub fn read_proc() -> Result<Vec<SeedProcess>, ProcfsError> {
    let mut processes = HashMap::new();
    for pid in procfs::get_running_processes()? {
        if let Some(process) = read_process(pid) {
            processes.insert(process.pid, process);
        }
    }
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for process in processes.values() {
        children.entry(process.ppid).or_default().push(process.pid);
    }
    let mut queue: VecDeque<u32> = processes
        .values()
        .filter(|process| !processes.contains_key(&process.ppid))
        .map(|process| process.pid)
        .collect();
    let mut ordered = Vec::with_capacity(processes.len());
    let mut seen = HashSet::new();
    while let Some(pid) = queue.pop_front() {
        if !seen.insert(pid) {
            continue;
        }
        queue.extend(children.get(&pid).into_iter().flatten());
        if let Some(process) = processes.remove(&pid) {
            ordered.push(process);
        }
    }
    Ok(ordered)
}

fn read_process(pid: Pid) -> Option<SeedProcess> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Fields after the parenthesised command name start at field 3 (state);
    // starttime is field 22.
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    let start_ticks = fields.get(22 - 3)?.parse().ok()?;
    let membership = match procfs::get_process_container_id(pid).ok()? {
        None => Membership::Host,
        Some(ContainerId::Docker(id)) => Membership::Container(Container {
            engine: "docker".to_string(),
            id,
        }),
        Some(ContainerId::Libpod(id)) => Membership::Container(Container {
            engine: "podman".to_string(),
            id,
        }),
    };
    Some(SeedProcess {
        pid: pid.as_raw() as u32,
        ppid: procfs::get_process_parent_pid(pid).ok()?.as_raw() as u32,
        start_ticks,
        uid: procfs::get_process_user_id(pid).ok()?.as_raw(),
        gid: procfs::get_process_group_id(pid).ok()?.as_raw(),
        image: procfs::get_process_image(pid)
            .ok()
            .map(|image| image.to_string_lossy().into_owned()),
        membership: Some(membership),
    })
}

/// Fills the probes' interest map for `processes`, the way bpf-filtering's
/// initializer does. Processes the probes already added are left alone.
pub fn seed_interest(
    ebpf: &mut Ebpf,
    config: &FilteringConfig,
    processes: &[SeedProcess],
) -> anyhow::Result<()> {
    let map = ebpf
        .map_mut(&config.interest_map_name)
        .with_context(|| format!("map {} not found", config.interest_map_name))?;
    let mut interest: BpfHashMap<_, i32, u8> = BpfHashMap::try_from(map)?;
    let mut decided: HashMap<u32, PolicyDecision> = HashMap::new();
    for process in processes {
        let inherited = decided
            .get(&process.ppid)
            .map_or(config.track_by_default, |parent| {
                parent.children_interesting
            });
        let mut decision = PolicyDecision {
            interesting: inherited,
            children_interesting: inherited,
        };
        let image = process.image.as_deref().unwrap_or_default();
        if let Some(rule) = config
            .rules
            .iter()
            .find(|rule| rule.image.to_string() == image)
        {
            decision.interesting = rule.track;
            if rule.with_children {
                decision.children_interesting = rule.track;
            }
        }
        if let Some(rule) = config
            .pid_targets
            .iter()
            .find(|rule| rule.pid.as_raw() as u32 == process.pid)
        {
            decision.interesting = true;
            if rule.with_children {
                decision.children_interesting = true;
            }
        }
        decided.insert(process.pid, decision);
        let pid = process.pid as i32;
        if interest.get(&pid, 0).is_err() {
            interest.insert(pid, decision.as_raw(), 0)?;
        }
    }
    Ok(())
}
