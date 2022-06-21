use bpf_common::{
    aya::{maps::MapError, Bpf},
    Pid, ProgramError,
};

use super::{maps::PolicyDecision, Config, InterestMap, ProcessData, RuleMap};

pub(crate) struct Initializer {
    interest_map: InterestMap,
    cache: std::collections::HashMap<Pid, PolicyDecision>,
    config: Config,
    my_pid: Pid,
}

impl Initializer {
    pub(crate) fn new(bpf: &mut Bpf, config: Config) -> Result<Self, ProgramError> {
        // setup targets map
        let mut target_map = RuleMap::target(bpf)?;
        target_map.clear()?;
        target_map.install(&config.targets)?;

        // setup whitelist map
        let mut whitelist_map = RuleMap::whitelist(bpf)?;
        whitelist_map.clear()?;
        whitelist_map.install(&config.whitelist)?;

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

    // These must be in order
    // - for each process (pid&image), we make a `PolicyDecision` by applying our list of rules.
    // - the output is stored in the interest map
    // - the output `children_interesting` is reused for the children and is passed to
    //   the closure as `inherited_interest`
    pub(crate) fn update(&mut self, process: &ProcessData) -> Result<(), MapError> {
        let parent_result = self.cache.get(&process.parent).copied().unwrap_or_default();
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
