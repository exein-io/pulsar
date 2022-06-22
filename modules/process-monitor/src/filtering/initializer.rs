use std::time::Duration;

use bpf_common::{
    aya::{maps::MapError, Bpf},
    Pid,
};
use pulsar_core::{
    pdk::{
        process_tracker::{ProcessTrackerHandle, TrackerUpdate},
        ModuleError,
    },
    Timestamp,
};
use tokio::sync::mpsc;

use super::{
    config::Config,
    maps::InterestMap,
    maps::{PolicyDecision, RuleMap},
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
    config: Config,
    process_tracker: &ProcessTrackerHandle,
    rx_processes: &mut mpsc::UnboundedReceiver<TrackerUpdate>,
) -> Result<(), ModuleError> {
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
        });
    }

    // apply pending changes
    let mut apply_new_events = || -> Result<(), ModuleError> {
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
    my_pid: Pid,
}

impl Initializer {
    fn new(bpf: &mut Bpf, config: Config) -> Result<Self, MapError> {
        // clear whitelist map
        let mut interest_map = InterestMap::load(bpf)?;
        interest_map.clear()?;

        let cache = Default::default();
        let my_pid = Pid::from_raw(std::process::id() as i32);

        Ok(Self {
            interest_map,
            cache,
            config,
            my_pid,
        })
    }

    fn update(&mut self, process: &ProcessData) -> Result<(), MapError> {
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
        let config = &self.config;
        let whitelist_match = config.whitelist.iter().find(|r| r.image == process.image);
        let targets_match = config.targets.iter().find(|r| r.image == process.image);
        let pid_targets_match = config.pid_targets.iter().find(|r| r.pid == process.pid);
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
        // make sure to ignore pulsard
        if process.pid == self.my_pid {
            decision = PolicyDecision {
                interesting: false,
                children_interesting: false,
            };
        }
        if decision.interesting {
            log::debug!("tracking {} {}", process.pid, process.image);
        }
        self.cache.insert(process.pid, decision);
        self.interest_map.set(process.pid, decision)?;
        Ok(())
    }
}
