//! # Events filtering
//!
//! This module contains the logic for implementing event filtering:
//! deciding wether an event is interesting for the rest of the system
//! or if it should be discarded.
//!
//! # Policy system requirements
//!
//! - Filtering should always happen on kernel side (for performance and consistency)
//! - Support for global monitoring (for lightweight probes scenarios like process/fs/network monitor)
//! - Support for very specific monitoring (for heavy probes scenarios like process anomaly/syscall monitor)
//! - Allow whitelist of uninteresting processes
//! - Allow specification of multiple targets
//!
//! # General design
//!
//! We allow user to specify:
//! - Targets: a list of processes we're interested in
//!   - each target is either a Pid or an Image (the executable path)
//!     - Pid targets are checked only on startup
//!   - specifies if we should consider its children as targets as well
//! - Whitelist: a list of processes we're not interested in
//!   - always specified with Image
//!   - specifies if we should consider its children as whitelist as well
//!
//! By default everything is interesting.
//! We do filtering based on process id, we ignore thread id.
//!
//! # Implementation
//!
//! Filtering must be done on kernel side, so we need several maps:
//!
//! **`(pinned) interesting: HashMap<Pid, struct { interesting: bool, children_interesting: bool}>`**
//! - Contains all processes and weather we should generate events for them or their children.
//! - It's initialized by userspace on startup by checking `procfs`
//! - It's updated by `process_monitor` on fork/exec/exit events
//!   - on fork we set `interesting[child pid] = interesting[parent pid].children_interesting`
//! - It's consulted by every other probe before executing
//!
//! **`whitelist: HasMap<Image, bool>`**
//! - Contains the whitelist images and weather the "whitelist" status extends to children
//! - Generated and updated by userspace.
//! - It's consulted by `process_monitor` on `exec` to check if we should update something
//!   - If exec image is in whitelist we set `interesting[my pid].interesting = false`
//!   - if exec image is in whitelist and extended to children, we set `interesting[my pid].children_interesting = false`
//!
//! **`targets: HasMap<Image, bool>`**
//! - Contains the target images and weather the "target" status extends to children
//! - Generated and updated by userspace.
//! - It's consulted by `process_monitor` on `exec` to check if we should update something
//!   - If exec image is in target we set `interesting[my pid].interesting = true`
//!   - if exec image is in whitelist and extended to children, we set `interesting[my pid].children_interesting = true`
//!
//! ## Startup procedure
//!
//! We empty the `interesting` map.
//! We should check `procfs` and build a tree of all interesting.
//! We build the `interesting` map by starting from pid 0 and applying recursively the choices above by checking the process `/proc/{}/exe`.

use bpf_common::{
    aya::{
        maps::{HashMap, MapError, MapRefMut},
        Bpf,
    },
    parsing::procfs::{self, ProcfsError},
};
use nix::unistd::Pid;

/// [`FilteringPolicy`] is the user configuration of a list of rules
/// for determining what constitutes an interesting eBPF event.
/// On startup, you should call `FilteringPolicy::install` to send all
/// rules to kernel side.
#[derive(Clone, Debug, Default)]
pub struct FilteringPolicy {
    pub(crate) pid_targets: Vec<PidRule>,
    pub(crate) targets: Vec<Rule>,
    pub(crate) whitelist: Vec<Rule>,
}

#[derive(Clone, Debug)]
pub struct Rule {
    /// This rule applies to all processes matching this process name
    pub(crate) image: String,
    /// If true, this rule is applied to all children of this process
    /// until a new rule with `with_children=true` applies.
    pub(crate) with_children: bool,
}

/// Rule for targeting a specific PID optionally its children
#[derive(Clone, Debug)]
pub struct PidRule {
    pub(crate) pid: Pid,
    pub(crate) with_children: bool,
}

impl FilteringPolicy {
    /// One-time operation to synchronize the set of rules to kernel side maps.
    ///
    /// This method takes a `bpf: &mut aya::Bpf` context where it will setup the maps.
    ///
    /// The most important is the `interest` map, which used by all probes to determine
    /// if an event should be emitted or not:
    /// - `procfs` is searched for running processes
    /// - the rules in `FilteringPolicy` are applied
    /// - the resulting `PolicyDecision` of each process is stored in the `interest` map
    ///
    /// The `target` and `whitelist` maps contain the actual rules and are needed by process
    /// monitor to update the `interest` map on fork/exec/exit.
    ///
    /// # Error handling
    /// This is a best effort process since some informations might be missing from `procfs`.
    /// We return an error only for eBPF map operations.
    pub fn install(self, bpf: &mut Bpf) -> Result<(), MapError> {
        let mut target_map = RuleMap::target(bpf)?;
        target_map.clear()?;
        target_map.install(&self.targets)?;

        // setup whitelist map
        let mut whitelist_map = RuleMap::whitelist(bpf)?;
        whitelist_map.clear()?;
        whitelist_map.install(&self.whitelist)?;

        // setup interest map
        let mut interest_map = InterestMap::load(bpf)?;
        interest_map.clear()?;
        match ProcessTree::load_from_procfs() {
            Err(err) => {
                log::error!("Error loading process list from procfs: {}", err);
                log::error!("interest map will be uninitialized");
            }
            Ok(processes) => {
                let my_pid = Pid::from_raw(std::process::id() as i32);
                // build the interest map by applying this closure recursively:
                // - for each process (pid&image), we make a `PolicyDecision` by applying our list of rules.
                // - the output is stored in the interest map
                // - the output `children_interesting` is reused for the children and is passed to
                //   the closure as `inherited_interest`
                processes.build(&mut interest_map, |pid, image, inherited_interest| {
                    // make sure to ignore pulsard
                    if pid == my_pid {
                        return PolicyDecision {
                            interesting: false,
                            children_interesting: false,
                        };
                    }
                    let mut decision = PolicyDecision {
                        interesting: inherited_interest,
                        children_interesting: inherited_interest,
                    };
                    if let Some(rule) = self.whitelist.iter().find(|r| r.image == image) {
                        decision.interesting = false;
                        if rule.with_children {
                            decision.children_interesting = false;
                        }
                    };
                    if let Some(rule) = self.targets.iter().find(|r| r.image == image) {
                        decision.interesting = true;
                        if rule.with_children {
                            decision.children_interesting = true;
                        }
                    };
                    if let Some(rule) = self.pid_targets.iter().find(|r| r.pid == pid) {
                        decision.interesting = true;
                        if rule.with_children {
                            decision.children_interesting = true;
                        }
                    };
                    if decision.interesting {
                        log::debug!("tracking {pid} {image}");
                    }
                    decision
                })?;
            }
        }
        Ok(())
    }
}

/// This map assigns to every running process a PolicyDecision:
/// - Are we interested in events generated by this process?
/// - Are we interested in events generated by its children?
struct InterestMap(HashMap<MapRefMut, i32, u8>);

#[derive(Clone, Copy)]
struct PolicyDecision {
    interesting: bool,
    children_interesting: bool,
}

impl Default for PolicyDecision {
    fn default() -> Self {
        Self {
            interesting: true,
            children_interesting: true,
        }
    }
}

impl PolicyDecision {
    /// Convert the `PolicyDecision` to a bit field
    fn as_raw(&self) -> u8 {
        match (self.children_interesting, self.interesting) {
            (false, false) => 0,
            (false, true) => 1,
            (true, false) => 2,
            (true, true) => 3,
        }
    }
}

impl InterestMap {
    /// Try to load the map from eBPF
    pub fn load(bpf: &mut Bpf) -> Result<Self, MapError> {
        let map = HashMap::try_from(bpf.map_mut("map_interest")?)?;
        Ok(Self(map))
    }

    /// Clear the map
    pub fn clear(&mut self) -> Result<(), MapError> {
        let old_processes: Result<Vec<i32>, _> = self.0.keys().collect();
        old_processes?
            .iter()
            .try_for_each(|pid| self.0.remove(pid))?;
        Ok(())
    }

    /// Update the interest map by setting the policy decision of a given process
    fn set(&mut self, pid: Pid, policy_result: PolicyDecision) -> Result<(), MapError> {
        self.0.insert(pid.as_raw(), policy_result.as_raw(), 0)?;
        Ok(())
    }
}

/// A RuleMap contains the target/whitelist images and weather or not the rule
/// should affect its children.
/// Whitelist and target list have the same fields, so we use a single struct for both.
struct RuleMap(HashMap<MapRefMut, Image, u8>);

#[derive(Clone, Copy)]
struct Image([u8; MAX_IMAGE_LEN]);
const MAX_IMAGE_LEN: usize = 100;
// We must explicitly mark Image as a plain old data which can be safely memcopied by aya.
unsafe impl bpf_common::aya::Pod for Image {}

impl RuleMap {
    /// Try to load the whitelist map
    pub fn whitelist(bpf: &mut Bpf) -> Result<Self, MapError> {
        let map = HashMap::try_from(bpf.map_mut("whitelist")?)?;
        Ok(Self(map))
    }

    /// Try to load the target map
    pub fn target(bpf: &mut Bpf) -> Result<Self, MapError> {
        let map = HashMap::try_from(bpf.map_mut("target")?)?;
        Ok(Self(map))
    }

    /// Clear the map
    pub fn clear(&mut self) -> Result<(), MapError> {
        let old_processes: Result<Vec<_>, _> = self.0.keys().collect();
        old_processes?
            .iter()
            .try_for_each(|image| self.0.remove(image))?;
        Ok(())
    }

    /// Fill the map with a list of rules
    fn install(&mut self, rules: &Vec<Rule>) -> Result<(), MapError> {
        for rule in rules {
            let mut src: Vec<u8> = rule.image.bytes().collect();
            if src.len() >= MAX_IMAGE_LEN {
                log::warn!("Image name is too long {:?}", rule);
            }
            src.resize(MAX_IMAGE_LEN, 0);
            let mut image: Image = Image([0; MAX_IMAGE_LEN]);
            image.0.clone_from_slice(&src[..]);
            let value: u8 = if rule.with_children { 1 } else { 0 };
            self.0.insert(image, value, 0)?;
        }
        Ok(())
    }
}

/// ProcessTree contains information about all running processes
struct ProcessTree {
    processes: Vec<ProcessData>,
}

struct ProcessData {
    pid: Pid,
    image: String,
    parent: Pid,
}

impl ProcessTree {
    /// Construct the `ProcessTree` by reading from `procfs`:
    /// - process list
    /// - parent pid
    /// - image
    fn load_from_procfs() -> Result<Self, ProcfsError> {
        let mut processes: Vec<ProcessData> = procfs::get_running_processes()?
            .into_iter()
            .map(|pid| {
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
                ProcessData { pid, image, parent }
            })
            .collect();
        // Make sure to add PID 0 (which is part of kernel) to map_interest to avoid
        // warnings about missing entries.
        processes.push(ProcessData {
            pid: Pid::from_raw(0),
            image: String::from("kernel"),
            parent: Pid::from_raw(0),
        });
        processes.sort_by_key(|p| p.pid);
        Ok(Self { processes })
    }

    /// Apply the given policy on every process.
    /// The policy function takes the process informations and the PolicyDecision of the process parent.
    /// It returns the PolicyDecision for the given process.
    /// The result is stored on interest_map and used for the next `policy` calls.
    fn build<F>(self, interest_map: &mut InterestMap, policy: F) -> Result<(), MapError>
    where
        F: Fn(Pid, String, bool) -> PolicyDecision,
    {
        let mut cache: std::collections::HashMap<Pid, PolicyDecision> = Default::default();
        self.processes.into_iter().try_for_each(|process| {
            // TODO: we may have no parent_result if more than `/proc/sys/kernel/pid_max`
            // processes have already spawn and the pid number restarted from 0.
            // We should build a proper tree structure and do a breath first search.
            let parent_result = cache.get(&process.parent).copied().unwrap_or_default();
            let current_result = policy(
                process.pid,
                process.image,
                parent_result.children_interesting,
            );
            cache.insert(process.pid, current_result);
            interest_map.set(process.pid, current_result)?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use bpf_common::program::load_test_program;
    use nix::unistd::execv;

    use super::*;
    use crate::tests::*;
    use crate::*;

    /// Make sure *fork* is extending interest to child
    #[test]
    // Running multiple tests in parallel will result in a messed up interest map
    // since it's pinned. We use serial_test to run them one by one.
    #[serial_test::serial]
    fn inherit_policy() {
        for (parent_value, interest_in_child) in [
            // if we miss parent information, we have full interest in child
            (None, true),
            // only children interest should be inherited by child
            (Some((true, true)), true),
            (Some((false, true)), true),
            (Some((true, false)), false),
            (Some((false, false)), false),
        ] {
            // load ebpf and clear interest map
            let mut bpf = load_test_program(process_monitor_ebpf()).unwrap();
            attach_fork_kprobe(&mut bpf);
            let mut interest_map = InterestMap::load(&mut bpf).unwrap();
            interest_map.clear().unwrap();

            // set the parent interest before forking the child
            if let Some(parent_value) = parent_value {
                let parent_value = PolicyDecision {
                    interesting: parent_value.0,
                    children_interesting: parent_value.1,
                }
                .as_raw();
                let pid = std::process::id() as i32;
                interest_map.0.insert(pid, parent_value, 0).unwrap();
            }

            // fork the child
            let child_pid = fork_and_return(0).as_raw() as i32;

            // make sure the eBPF fork code expanded interest to the child
            let expected_interest = PolicyDecision {
                interesting: interest_in_child,
                children_interesting: interest_in_child,
            }
            .as_raw();
            println!("expecting {child_pid}={expected_interest}");
            let actual_interest = interest_map.0.get(&child_pid, 0).unwrap();
            assert_eq!(expected_interest, actual_interest);
        }
    }

    /// Make sure *exec* is checking whitelist and target map to update interest
    #[test]
    #[serial_test::serial]
    fn exec_updates_interest() {
        // for each rule type (whitelist, whitelist&children, target, target&children)
        // check if exec is updating it as expected
        for (is_target, with_children) in
            [(true, true), (true, false), (false, true), (false, false)]
        {
            // load ebpf and clear interest map
            let mut bpf = load_test_program(process_monitor_ebpf()).unwrap();
            attach_tracepoint(&mut bpf, "sched_process_exec");
            let mut interest_map = InterestMap::load(&mut bpf).unwrap();
            interest_map.clear().unwrap();

            // add rule to target echo
            let image = "/usr/bin/echo";
            let rule = Rule {
                image: image.to_string(),
                with_children,
            };
            let rules = vec![rule];
            let mut rule_map = if is_target {
                RuleMap::target(&mut bpf).unwrap()
            } else {
                RuleMap::whitelist(&mut bpf).unwrap()
            };
            rule_map.clear().unwrap();
            rule_map.install(&rules).unwrap();

            // set old value to wrong value to make sure we're making a change
            // try both values of with_children
            for old_with_children in [true, false] {
                // run the targeted command
                let interest_map_ref = &mut interest_map;
                let child_pid = fork_and_run(move || {
                    // before calling exec, we want to update our interest
                    let old_value = PolicyDecision {
                        interesting: !is_target,
                        children_interesting: old_with_children,
                    }
                    .as_raw();
                    let pid = std::process::id() as i32;
                    interest_map_ref.0.insert(pid, old_value, 0).unwrap();
                    execv(
                        &CString::new(image).unwrap(),
                        &[CString::new("hello world").unwrap()],
                    )
                    .unwrap();
                    unreachable!();
                })
                .as_raw();

                // make sure the eBPF exec code updated interest
                let expected_interest = PolicyDecision {
                    interesting: is_target,
                    children_interesting: if with_children {
                        is_target
                    } else {
                        old_with_children
                    },
                }
                .as_raw();
                println!("is_target={is_target} with_children={with_children} old_with_children={old_with_children}");
                println!("expecting {child_pid}={expected_interest}");
                let actual_interest = interest_map.0.get(&child_pid, 0).unwrap();
                assert_eq!(expected_interest, actual_interest);
            }
        }
    }

    // attach a single tracepoint for test purposes
    fn attach_tracepoint(bpf: &mut Bpf, tp: &str) {
        let tracepoint: &mut TracePoint = bpf
            .program_mut(tp)
            .ok_or(ProgramError::ProgramNotFound(tp.to_string()))
            .unwrap()
            .try_into()
            .unwrap();
        tracepoint.load().unwrap();
        tracepoint.attach("sched", tp).unwrap();
    }

    fn attach_fork_kprobe(bpf: &mut Bpf) {
        let kprobe: &mut KProbe = bpf
            .program_mut("wake_up_new_task")
            .unwrap()
            .try_into()
            .unwrap();
        kprobe.load().unwrap();
        kprobe.attach("wake_up_new_task", 0).unwrap();
    }

    /// Make sure by default we're tracking everything but ourself
    #[test]
    #[serial_test::serial]
    fn self_is_ignored() {
        let mut bpf = load_test_program(process_monitor_ebpf()).unwrap();
        let policy = FilteringPolicy {
            pid_targets: vec![],
            targets: vec![],
            whitelist: vec![],
        };
        policy.install(&mut bpf).unwrap();
        let interest_map = InterestMap::load(&mut bpf).unwrap();
        let my_pid = std::process::id() as i32;
        for item in interest_map.0.iter() {
            let (key, value) = item.unwrap();
            if key != my_pid {
                assert_eq!(value, 3);
            }
        }
        assert_eq!(interest_map.0.get(&my_pid, 0).unwrap(), 0);
    }

    /// map_interest should not include thread entries because it would
    /// fill the map with useless data.
    #[test]
    #[serial_test::serial]
    fn threads_are_ignored() {
        // load ebpf and clear interest map
        let mut bpf = load_test_program(process_monitor_ebpf()).unwrap();
        attach_fork_kprobe(&mut bpf);
        let mut interest_map = InterestMap::load(&mut bpf).unwrap();
        interest_map.clear().unwrap();

        // try spawning a new thread
        let child_thread = std::thread::spawn(|| nix::unistd::gettid())
            .join()
            .unwrap()
            .as_raw();
        let our_pid = std::process::id() as i32;

        // make sure we've not created an interest entry for it
        assert!(interest_map.0.get(&child_thread, 0).is_err());
        // make sure we've not overridden the parent interest
        // with the child one.
        assert!(interest_map.0.get(&our_pid, 0).is_err());
    }

    /// exit hook must delete elements from map_interest
    #[test]
    #[serial_test::serial]
    fn exit_cleans_up_resources() {
        // setup
        let mut bpf = load_test_program(process_monitor_ebpf()).unwrap();
        attach_tracepoint(&mut bpf, "sched_process_exit");
        let mut interest_map = InterestMap::load(&mut bpf).unwrap();
        interest_map.clear().unwrap();

        let interest_map_ref = &mut interest_map;
        let child_pid = fork_and_run(move || {
            let pid = std::process::id() as i32;
            interest_map_ref.0.insert(pid, 0, 0).unwrap();
            std::process::exit(0);
        })
        .as_raw();

        // make sure exit hook deleted it
        assert!(interest_map.0.get(&child_pid, 0).is_err());
    }
}
