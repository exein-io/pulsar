use std::{os::unix::prelude::OsStringExt, time::Duration};

use anyhow::{Context, Result};
use bpf_common::{Pid, aya::Ebpf};
use pulsar_core::{
    Timestamp,
    pdk::process_tracker::{ProcessTrackerHandle, TrackerUpdate},
};
use tokio::sync::mpsc;

use crate::maps::{Cgroup, Map};

use super::{
    config::{Config, Rule},
    maps::InterestMap,
    maps::{Image, PolicyDecision, RuleMap},
    process_tree::{PID_0, ProcessData, ProcessTree},
};

const INIT_TIMEOUT: Duration = Duration::from_millis(100);

/// Setup maps and process tracker by reading from procfs.
///
/// In order not to lose anything, this strategy is used:
/// 1. Start process-tracker eBPF
/// 2. Setup targets and whitelist map:
///    eBPF code will start applying these rules on newly spawned processes.
/// 3. Load existing processes from procfs
///    - initialize map_interest
///    - initialize process tracker
/// 4. Apply events generated since step 1:
///    this makes sure the eBPF code didn't fill map_interest with wrong data
///    because of unitialized entries.
pub async fn setup_events_filter(
    bpf: &mut Ebpf,
    mut config: Config,
    process_tracker: &ProcessTrackerHandle,
    rx_processes: &mut mpsc::UnboundedReceiver<TrackerUpdate>,
) -> Result<()> {
    // Add a rule to ignore the pulsar executable itself
    if config.ignore_self {
        match whitelist_for_current_process().await {
            Ok(rule) => config.rules.push(rule),
            Err(err) => log::error!("Failed to add current process to whitelist: {:?}", err),
        }
    }

    // setup rule map
    let mut target_map = RuleMap::load(bpf, &config.rule_map_name)?;
    target_map.clear()?;
    target_map.install(&config.rules)?;

    // setup cgroup rule map
    let mut cgroups_map = Map::<Cgroup, u8>::load(bpf, &config.cgroup_rule_map_name)?;
    cgroups_map.clear()?;
    for cgroup in &config.cgroup_targets {
        let cgroup: Cgroup = cgroup.parse().context("Invalid target cgroup")?;
        cgroups_map
            .map
            .insert(cgroup, 0, 0)
            .context("Error inserting in cgroup rule map")?;
    }

    // load process list from BPF iterator
    let mut process_tree = ProcessTree::load_from_bpf_iterator(bpf)?;

    let mut initializer = Initializer::new(bpf, config)?;
    if let Err(err) = initializer.track_target_cgroups().await {
        log::warn!("Error loading cgroup information: {err:?}");
    }
    for process in &process_tree {
        initializer.update(process)?;
        process_tracker.update(TrackerUpdate::Fork {
            ppid: process.parent,
            pid: process.pid,
            uid: process.uid,
            gid: process.gid,
            timestamp: Timestamp::from(0),
            namespaces: process.namespaces,
            container_id: process.container_id.clone(),
        });
        process_tracker.update(TrackerUpdate::Exec {
            pid: process.pid,
            uid: process.uid,
            image: process.image.to_string(),
            timestamp: Timestamp::from(0),
            argv: Vec::new(),
            namespaces: process.namespaces,
            container_id: process.container_id.clone(),
        });
    }

    // apply pending changes
    let mut apply_new_events = || -> Result<()> {
        while let Ok(update) = rx_processes.try_recv() {
            match &update {
                TrackerUpdate::Fork {
                    pid,
                    ppid,
                    uid,
                    gid,
                    namespaces,
                    container_id,
                    ..
                } => initializer.update(process_tree.fork(
                    *pid,
                    *ppid,
                    *uid,
                    *gid,
                    *namespaces,
                    container_id.clone(),
                )?)?,
                TrackerUpdate::Exec { pid, image, .. } => {
                    initializer.update(process_tree.exec(*pid, image)?)?
                }
                TrackerUpdate::Exit { .. } | TrackerUpdate::SetNewParent { .. } => {}
            };
            process_tracker.update(update);
        }
        Ok(())
    };
    apply_new_events()?;
    // We want to give the eBPF code enough time to catch up with the
    // updated map_interest, so we wait INIT_TIMEOUT and check if we missed
    // anything.
    tokio::time::sleep(INIT_TIMEOUT).await;
    apply_new_events()?;

    Ok(())
}

/// Initializer of map_interest
struct Initializer {
    interest_map: InterestMap,
    cache: std::collections::HashMap<Pid, PolicyDecision>,
    config: Config,
}

impl Initializer {
    fn new(bpf: &mut Ebpf, config: Config) -> Result<Self> {
        let mut interest_map = InterestMap::load(bpf, &config.interest_map_name)?;
        // clear interest map
        interest_map.clear()?;
        let cache = Default::default();

        Ok(Self {
            interest_map,
            cache,
            config,
        })
    }

    fn update(&mut self, process: &ProcessData) -> Result<()> {
        // If we're already tracking a process, we don't want to override that decision and stop
        // tracking it. This is useful for cgroups, which are checked before process hierarchy
        if matches!(
            self.cache.get(&process.pid),
            Some(PolicyDecision {
                interesting: true,
                children_interesting: true,
            })
        ) {
            return Ok(());
        }
        let parent_result = self.cache.get(&process.parent).copied().unwrap_or_else(|| {
            if process.pid != PID_0 {
                log::warn!(
                    "process {} not found while building map_interest",
                    process.parent
                );
            }
            PolicyDecision {
                interesting: self.config.track_by_default,
                children_interesting: self.config.track_by_default,
            }
        });
        let inherited_interest = parent_result.children_interesting;
        let mut decision = PolicyDecision {
            interesting: inherited_interest,
            children_interesting: inherited_interest,
        };
        let rule_match = self
            .config
            .rules
            .iter()
            .find(|r| r.image.to_string() == process.image);
        let pid_targets_match = self
            .config
            .pid_targets
            .iter()
            .find(|r| r.pid == process.pid);
        if let Some(rule) = rule_match {
            decision.interesting = rule.track;
            if rule.with_children {
                decision.children_interesting = rule.track;
            }
        };
        if let Some(rule) = pid_targets_match {
            decision.interesting = true;
            if rule.with_children {
                decision.children_interesting = true;
            }
        };
        if decision.interesting {
            log::debug!("tracking {} {}", process.pid, process.image);
        }
        self.set_policy(process.pid, decision)
    }

    fn set_policy(&mut self, pid: Pid, policy: PolicyDecision) -> Result<()> {
        log::trace!("Set policy for {}: {}", pid, policy.as_raw());
        self.cache.insert(pid, policy);
        self.interest_map.set(pid, policy)
    }

    async fn track_target_cgroups(&mut self) -> Result<()> {
        let cgroups: Vec<String> = self
            .config
            .cgroup_targets
            .iter()
            // the cgroup.procfs file contains the list of pids belonging to this cgroup
            .map(|cgroup| format!("/sys/fs/cgroup{cgroup}/cgroup.procs"))
            .collect();
        for cgroup in cgroups {
            let processes = tokio::fs::read_to_string(&cgroup)
                .await
                .with_context(|| format!("Error reading processes in cgroup {:?}", cgroup))?;
            for process in processes.lines() {
                let pid: i32 = process.parse().context("Invalid content")?;
                self.set_policy(
                    Pid::from_raw(pid),
                    PolicyDecision {
                        interesting: true,
                        children_interesting: true,
                    },
                )?;
            }
        }
        Ok(())
    }
}

/// Return a rule which whitelists the current executable.
/// This is needed to avoid loops where pulsar events generate further events.
async fn whitelist_for_current_process() -> Result<Rule> {
    let pulsar_exec = tokio::fs::read_link("/proc/self/exe")
        .await
        .context("Failed to read current process executable name")?;
    Ok(Rule {
        image: Image::try_from(pulsar_exec.into_os_string().into_vec())?,
        with_children: true,
        track: false,
    })
}
