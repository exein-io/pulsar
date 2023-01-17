use std::{os::unix::prelude::OsStringExt, time::Duration};

use anyhow::{Context, Result};
use bpf_common::{aya::Bpf, Pid};
use pulsar_core::{
    pdk::process_tracker::{ProcessTrackerHandle, TrackerUpdate},
    Timestamp,
};
use tokio::sync::mpsc;

use super::{
    config::{Config, Rule},
    maps::InterestMap,
    maps::{Image, PolicyDecision, RuleMap},
    process_tree::{ProcessData, ProcessTree, PID_0},
};

const INIT_TIMEOUT: Duration = Duration::from_millis(100);

/// Setup maps and process tracker by reading from procfs.
///
/// In order not to loose anything, this strategy is used:
/// 1. Start process-tracker eBPF
/// 2. Setup targets and whitelist map:
///    eBPF code will start applying these rules on newly spawned processes.
/// 3. Load existing processes from procfs
///    - initialize map_interest
///    - initialize process tracker
/// 4. Apply events generated since step 1:
///    this makes sure the eBPF code didn't fill map_interest with wrong data
///    because of unitialized entries.
pub(crate) async fn setup_events_filter(
    bpf: &mut Bpf,
    mut config: Config,
    process_tracker: &ProcessTrackerHandle,
    rx_processes: &mut mpsc::UnboundedReceiver<TrackerUpdate>,
) -> Result<()> {
    // Add a rule to ignore the pulsar executable itself
    if config.ignore_self {
        match whitelist_for_current_process() {
            Ok(rule) => config.whitelist.push(rule),
            Err(err) => log::error!("Failed to add current process to whitelist: {:?}", err),
        }
    }

    // setup targets map
    let mut target_map = RuleMap::target(bpf)?;
    target_map.clear()?;
    target_map.install(&config.targets)?;

    // setup whitelist map
    let mut whitelist_map = RuleMap::whitelist(bpf)?;
    whitelist_map.clear()?;
    whitelist_map.install(&config.whitelist)?;

    // load process list from procfs
    let mut process_tree = ProcessTree::load_from_procfs()?;

    let mut initializer = Initializer::new(bpf, config)?;
    for process in &process_tree {
        initializer.update(process)?;
        process_tracker.update(TrackerUpdate::Fork {
            ppid: process.parent,
            pid: process.pid,
            timestamp: Timestamp::from(0),
        });
        process_tracker.update(TrackerUpdate::Exec {
            pid: process.pid,
            image: process.image.to_string(),
            timestamp: Timestamp::from(0),
            argv: Vec::new(),
        });
    }

    // apply pending changes
    let mut apply_new_events = || -> Result<()> {
        while let Ok(update) = rx_processes.try_recv() {
            match &update {
                TrackerUpdate::Fork { pid, ppid, .. } => {
                    initializer.update(process_tree.fork(*pid, *ppid)?)?
                }
                TrackerUpdate::Exec { pid, image, .. } => {
                    initializer.update(process_tree.exec(*pid, image)?)?
                }
                TrackerUpdate::Exit { .. } => {}
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
    fn new(bpf: &mut Bpf, config: Config) -> Result<Self> {
        // clear whitelist map
        let mut interest_map = InterestMap::load(bpf)?;
        interest_map.clear()?;
        let cache = Default::default();

        Ok(Self {
            interest_map,
            cache,
            config,
        })
    }

    fn update(&mut self, process: &ProcessData) -> Result<()> {
        let parent_result = self.cache.get(&process.parent).copied().unwrap_or_else(|| {
            if process.pid != PID_0 {
                log::warn!(
                    "process {} not found while building map_interest",
                    process.parent
                );
            }
            PolicyDecision::default()
        });
        let inherited_interest = parent_result.children_interesting;
        let mut decision = PolicyDecision {
            interesting: inherited_interest,
            children_interesting: inherited_interest,
        };
        let whitelist_match = self
            .config
            .whitelist
            .iter()
            .find(|r| r.image.to_string() == process.image);
        let targets_match = self
            .config
            .targets
            .iter()
            .find(|r| r.image.to_string() == process.image);
        let pid_targets_match = self
            .config
            .pid_targets
            .iter()
            .find(|r| r.pid == process.pid);
        if let Some(rule) = whitelist_match {
            decision.interesting = false;
            if rule.with_children {
                decision.children_interesting = false;
            }
        };
        if let Some(rule) = targets_match {
            decision.interesting = true;
            if rule.with_children {
                decision.children_interesting = true;
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
        self.cache.insert(process.pid, decision);
        self.interest_map.set(process.pid, decision)?;
        Ok(())
    }
}

/// Return a rule which whitelists the current executable.
/// This is needed to avoid loops where pulsar events generate further events.
fn whitelist_for_current_process() -> Result<Rule> {
    let pulsar_exec = std::fs::read_link(&format!("/proc/{}/exe", std::process::id()))
        .context("Failed to read current process executable name")?;
    Ok(Rule {
        image: Image::try_from(pulsar_exec.into_os_string().into_vec())?,
        with_children: true,
    })
}
