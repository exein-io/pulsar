use crate::config::Rule;
use crate::maps::{Cgroup, InterestMap, Map, PolicyDecision, RuleMap};
use bpf_common::aya::programs::RawTracePoint;
use bpf_common::aya::{self, Bpf, BpfLoader};
use bpf_common::program::BpfContext;
use bpf_common::test_runner::{TestCase, TestReport, TestSuite};
use bpf_common::test_utils::cgroup::fork_in_temp_cgroup;
use bpf_common::test_utils::random_name_with_prefix;
use bpf_common::{ebpf_program, Pid, ProgramError};
use nix::unistd::execv;
use nix::unistd::{fork, ForkResult};
use std::ffi::CString;
use which::which;

const INTEREST_MAP_NAME: &str = "m_interest";
const RULE_MAP_NAME: &str = "m_rules";

pub fn tests() -> TestSuite {
    TestSuite {
        name: "filtering",
        tests: vec![
            inherit_policy(),
            exec_updates_interest(),
            threads_are_ignored(),
            exit_cleans_up_resources(),
            uninteresting_processes_ignored(),
            cgroups_tracked(),
        ],
    }
}

/// Fork current project and store child pid inside child_pid
pub fn fork_and_return(exit_code: u32) -> Pid {
    fork_and_run(move || std::process::exit(exit_code as i32))
}

pub fn fork_and_run(f: impl FnOnce()) -> Pid {
    match unsafe { fork() }.unwrap() {
        ForkResult::Child => {
            f();
            unreachable!();
        }
        ForkResult::Parent { child } => {
            nix::sys::wait::waitpid(child, None).unwrap();
            child
        }
    }
}

/// Make sure *fork* is extending interest to child
fn inherit_policy() -> TestCase {
    TestCase::new("inherit_policy", async {
        let mut report = TestReport {
            success: true,
            lines: vec![],
        };
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
            let mut bpf = load_ebpf();
            attach_raw_tracepoint(&mut bpf, "sched_process_fork");
            let mut interest_map = InterestMap::load(&mut bpf, INTEREST_MAP_NAME).unwrap();
            interest_map.clear().unwrap();

            // set the parent interest before forking the child
            if let Some(parent_value) = parent_value {
                let parent_value = PolicyDecision {
                    interesting: parent_value.0,
                    children_interesting: parent_value.1,
                }
                .as_raw();
                let pid = std::process::id() as i32;
                interest_map.0.map.insert(pid, parent_value, 0).unwrap();
            }

            // fork the child
            let child_pid = fork_and_return(0).as_raw();

            // make sure the eBPF fork code expanded interest to the child
            let expected_interest = PolicyDecision {
                interesting: interest_in_child,
                children_interesting: interest_in_child,
            }
            .as_raw();
            let actual_interest = interest_map.0.map.get(&child_pid, 0).ok();
            if Some(expected_interest) != actual_interest {
                report.lines.push(format!(
                    "expecting {child_pid}={expected_interest} (was {actual_interest:?})"
                ));
                report.success = false;
            } else {
                report
                    .lines
                    .push(format!("ok {child_pid}={expected_interest}"));
            }
        }
        report
    })
}

/// Make sure *exec* is checking whitelist and target map to update interest
fn exec_updates_interest() -> TestCase {
    TestCase::new("exec_updates_interest", async {
        let mut report = TestReport {
            success: true,
            lines: vec![],
        };
        // for each rule type (whitelist, whitelist&children, target, target&children)
        // check if exec is updating it as expected
        for (track, with_children) in [(true, true), (true, false), (false, true), (false, false)] {
            // load ebpf and clear interest map
            let mut bpf = load_ebpf();
            attach_raw_tracepoint(&mut bpf, "sched_process_exec");
            let mut interest_map = InterestMap::load(&mut bpf, INTEREST_MAP_NAME).unwrap();
            interest_map.clear().unwrap();

            // add rule to target echo
            let image = which("echo").unwrap().to_string_lossy().to_string();
            let mut rule_map = RuleMap::load(&mut bpf, RULE_MAP_NAME).unwrap();
            rule_map.clear().unwrap();
            rule_map
                .install(&[Rule {
                    image: image.parse().unwrap(),
                    track,
                    with_children,
                }])
                .unwrap();

            // set old value to wrong value to make sure we're making a change
            // try both values of with_children
            for old_with_children in [true, false] {
                // run the targeted command
                let interest_map_ref = &mut interest_map;
                let child_pid = fork_and_run(|| {
                    // before calling exec, we want to update our interest
                    let old_value = PolicyDecision {
                        interesting: !track,
                        children_interesting: old_with_children,
                    }
                    .as_raw();
                    let pid = std::process::id() as i32;
                    interest_map_ref.0.map.insert(pid, old_value, 0).unwrap();
                    let exec_binary = CString::new(image.as_str()).unwrap();
                    execv(
                        &exec_binary,
                        // -n flag suppresses echo newline character
                        &[exec_binary.clone(), CString::new("-n").unwrap()],
                    )
                    .unwrap();
                    unreachable!();
                })
                .as_raw();

                // make sure the eBPF exec code updated interest
                let expected_interest = PolicyDecision {
                    interesting: track,
                    children_interesting: if with_children {
                        track
                    } else {
                        old_with_children
                    },
                }
                .as_raw();
                let actual_interest = interest_map.0.map.get(&child_pid, 0).unwrap();
                if expected_interest != actual_interest {
                    report
                        .lines
                        .push(format!("track={track} with_children={with_children} old_with_children={old_with_children}"));
                    report.lines.push(format!(
                        "✗ expecting map_interest[{child_pid}] = {expected_interest} (was {actual_interest})"
                    ));
                    report.success = false;
                }
            }
        }
        report
    })
}

const INTERESTING: PolicyDecision = PolicyDecision {
    interesting: true,
    children_interesting: true,
};
const NOT_INTERESTING: PolicyDecision = PolicyDecision {
    interesting: false,
    children_interesting: false,
};

/// Make sure uninteresting events are not tracked.
/// This tests the tracker_interesting_tgid function, which should return -1 when
/// called from processes whose entry in m_interest is not INTEREST_TRACK_SELF.
fn uninteresting_processes_ignored() -> TestCase {
    TestCase::new("uninteresting_processes_ignored", async {
        let mut report = TestReport {
            success: true,
            lines: vec![],
        };
        let mut bpf = load_ebpf();
        attach_raw_tracepoint(&mut bpf, "sys_enter");

        let mut interest_map = InterestMap::load(&mut bpf, INTEREST_MAP_NAME).unwrap();
        interest_map.clear().unwrap();

        // Mark pid as "not interesting"
        let pid = std::process::id() as i32;
        interest_map
            .set(Pid::from_raw(pid), NOT_INTERESTING)
            .unwrap();

        // The skipped map will count how many times sys_enter was called by "non interesting" processes
        let mut skipped_map: aya::maps::HashMap<_, i32, u64> = aya::maps::HashMap::try_from(
            bpf.map_mut("skipped_map")
                .expect("Error finding eBPF map skipped_map"),
        )
        .unwrap();
        skipped_map.insert(pid, 0, 0).unwrap();
        let skipped_counter = skipped_map.get(&pid, 0).unwrap();

        // Make sure the counter has increased.
        // Notice how this generally happens the other way around: in pulsar events are emitted
        // only for "interesting" processes and "non interesting" processes are skipped.
        // This is why we've named the "skipped_map" like this. In this particular test-case
        // it's the other way around: we increase skipped_counter when we would ignore
        // a process.
        if skipped_counter == 0 {
            report
                .lines
                .push("✗ event for uninteresting process not skipped".to_string());
            report.success = false;
        }
        report
    })
}

// Make sure that when a process is attached to a target cgroup, it gets full interest
fn cgroups_tracked() -> TestCase {
    TestCase::new("cgroups_tracked", async {
        let mut report = TestReport {
            success: true,
            lines: vec![],
        };
        let mut bpf = load_ebpf();
        attach_raw_tracepoint(&mut bpf, "cgroup_attach_task");

        let mut interest_map = InterestMap::load(&mut bpf, INTEREST_MAP_NAME).unwrap();
        interest_map.clear().unwrap();

        let pid = std::process::id() as i32;
        interest_map
            .set(Pid::from_raw(pid), NOT_INTERESTING)
            .unwrap();

        let mut target_cgroup_map = Map::<Cgroup, u8>::load(&mut bpf, "m_cgroup_rules").unwrap();
        let cgroup = random_name_with_prefix("/cgroups_tracked");
        let cgroup_path: Cgroup = cgroup.parse().unwrap();
        target_cgroup_map.map.insert(cgroup_path, 0, 0).unwrap();

        // Spawn a process inside the targetted cgroup
        let (child_pid, _id) = fork_in_temp_cgroup(&cgroup[1..]);

        if interest_map.0.map.get(&child_pid.as_raw(), 0).unwrap() != INTERESTING.as_raw() {
            report.lines.push(
                "✗ process attached to target cgroup is still marked as not interesting"
                    .to_string(),
            );
            report.success = false;
        }

        report
    })
}

// attach a single tracepoint for test purposes
fn attach_raw_tracepoint(bpf: &mut Bpf, tp: &str) {
    let tracepoint: &mut RawTracePoint = bpf
        .program_mut(tp)
        .ok_or_else(|| ProgramError::ProgramNotFound(tp.to_string()))
        .unwrap()
        .try_into()
        .unwrap();
    tracepoint.load().unwrap();
    tracepoint.attach(tp).unwrap();
}

/// map_interest should not include thread entries because it would
/// fill the map with useless data.
fn threads_are_ignored() -> TestCase {
    TestCase::new("threads_are_ignored", async {
        // load ebpf and clear interest map
        let mut bpf = load_ebpf();
        attach_raw_tracepoint(&mut bpf, "sched_process_fork");
        let mut interest_map = InterestMap::load(&mut bpf, INTEREST_MAP_NAME).unwrap();
        interest_map.clear().unwrap();

        // try spawning a new thread
        let child_thread = std::thread::spawn(nix::unistd::gettid)
            .join()
            .unwrap()
            .as_raw();
        let our_pid = std::process::id() as i32;

        let mut report = TestReport {
            success: true,
            lines: vec![],
        };

        // make sure we've not created an interest entry for it
        if interest_map.0.map.get(&child_thread, 0).is_ok() {
            report.success = false;
            report
                .lines
                .push("unexpected entry for child thread".to_string())
        }
        // make sure we've not overridden the parent interest
        // with the child one.
        if interest_map.0.map.get(&our_pid, 0).is_ok() {
            report.success = false;
            report
                .lines
                .push("should not have overridden parent interest".to_string())
        }
        report
    })
}

/// exit hook must delete elements from map_interest
fn exit_cleans_up_resources() -> TestCase {
    TestCase::new("exit_cleans_up_resources", async {
        // setup
        let mut bpf = load_ebpf();
        attach_raw_tracepoint(&mut bpf, "sched_process_exit");
        let mut interest_map = InterestMap::load(&mut bpf, INTEREST_MAP_NAME).unwrap();
        interest_map.clear().unwrap();

        let interest_map_ref = &mut interest_map;
        let child_pid = fork_and_run(move || {
            let pid = std::process::id() as i32;
            interest_map_ref.0.map.insert(pid, 0, 0).unwrap();
            std::process::exit(0);
        })
        .as_raw();

        // make sure exit hook deleted it
        TestReport {
            success: interest_map.0.map.get(&child_pid, 0).is_err(),
            lines: vec![format!(
                "exit should have deleted PID {child_pid} from map_interest"
            )],
        }
    })
}

fn load_ebpf() -> Bpf {
    let ctx = BpfContext::new(
        bpf_common::program::Pinning::Disabled,
        bpf_common::program::PERF_PAGES_DEFAULT,
        bpf_common::program::BpfLogLevel::Debug,
    )
    .unwrap();
    const PIN_PATH: &str = "/sys/fs/bpf/filtering-test";
    let _ = std::fs::create_dir(PIN_PATH);
    let bpf = BpfLoader::new()
        .map_pin_path(PIN_PATH)
        .load(ebpf_program!(&ctx, "filtering_example").as_slice())
        .unwrap();
    bpf
}
