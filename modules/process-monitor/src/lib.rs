use std::fmt;

use bpf_common::{
    aya::include_bytes_aligned, parsing::StringArray, program::BpfContext, BpfSender, Pid, Program,
    ProgramBuilder, ProgramError,
};
mod filtering;

const MODULE_NAME: &str = "process-monitor";

pub async fn program(
    ctx: BpfContext,
    sender: impl BpfSender<ProcessEvent>,
) -> Result<Program, ProgramError> {
    let program = ProgramBuilder::new(ctx, MODULE_NAME, PROCESS_MONITOR_PROBE.into())
        .tracepoint("sched", "sched_process_exec")
        .tracepoint("sched", "sched_process_exit")
        .kprobe("wake_up_new_task")
        .start()
        .await?;
    program.read_events("events", sender).await?;
    Ok(program)
}

static PROCESS_MONITOR_PROBE: &[u8] =
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/probe.bpf.o"));

const NAME_MAX: usize = 264;

// The events sent from eBPF to userspace must be byte by byte
// re-interpretable as Rust types. So pointers to the heap are
// not allowed.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
#[repr(C)]
pub enum ProcessEvent {
    Fork { ppid: Pid },
    Exec { filename: StringArray<NAME_MAX> },
    Exit { exit_code: u32 },
}

impl fmt::Display for ProcessEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessEvent::Fork { ppid } => write!(f, "forked from {}", ppid),
            ProcessEvent::Exec { filename } => {
                write!(f, "exec {}", filename,)
            }
            ProcessEvent::Exit { exit_code } => write!(f, "exit({})", exit_code),
        }
    }
}

pub mod pulsar {
    use super::*;
    use bpf_common::{program::BpfEvent, BpfSenderWrapper};
    use pulsar_core::pdk::{
        process_tracker::TrackerUpdate, CleanExit, ModuleContext, ModuleError, Payload,
        PulsarModule, ShutdownSignal, Version,
    };
    use tokio::sync::mpsc;

    pub fn module() -> PulsarModule {
        PulsarModule::new(MODULE_NAME, Version::new(0, 0, 1), process_monitor_task)
    }

    async fn process_monitor_task(
        ctx: ModuleContext,
        mut shutdown: ShutdownSignal,
    ) -> Result<CleanExit, ModuleError> {
        let rx_config = ctx.get_cfg::<filtering::config::Config>();
        let filtering_config = rx_config.borrow().clone()?;
        let process_tracker = ctx.get_process_tracker();
        let (tx_processes, mut rx_processes) = mpsc::unbounded_channel();
        let mut program = program(
            ctx.get_bpf_context(),
            // When generating events we must update process_tracker.
            // We do this by wrapping the pulsar sender and calling this closure on every event.
            BpfSenderWrapper::new(ctx.get_sender(), move |event: &BpfEvent<ProcessEvent>| {
                let _ = tx_processes.send(match event.payload {
                    ProcessEvent::Fork { ppid } => TrackerUpdate::Fork {
                        pid: event.pid,
                        ppid,
                        timestamp: event.timestamp,
                    },
                    ProcessEvent::Exec { ref filename } => TrackerUpdate::Exec {
                        pid: event.pid,
                        image: filename.to_string(),
                        timestamp: event.timestamp,
                    },
                    ProcessEvent::Exit { .. } => TrackerUpdate::Exit {
                        pid: event.pid,
                        timestamp: event.timestamp,
                    },
                });
            }),
        )
        .await?;

        filtering::initializer::setup_events_filter(
            program.bpf(),
            filtering_config,
            &process_tracker,
            &mut rx_processes,
        )
        .await?;

        // rx_processes will first be used during initialization,
        // than it will be used to keep the process tracker updated

        loop {
            tokio::select! {
                r = shutdown.recv() => return r,
                Some(msg) = rx_processes.recv() => process_tracker.update(msg),
            }
        }
    }

    impl From<ProcessEvent> for Payload {
        fn from(data: ProcessEvent) -> Self {
            match data {
                ProcessEvent::Fork { ppid } => Payload::Fork {
                    ppid: ppid.as_raw(),
                },
                ProcessEvent::Exec { filename } => Payload::Exec {
                    filename: filename.to_string(),
                },
                ProcessEvent::Exit { exit_code } => Payload::Exit { exit_code },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::filtering::maps::PolicyDecision;
    use bpf_common::aya::programs::{KProbe, TracePoint};
    use bpf_common::aya::Bpf;
    use bpf_common::program::load_test_program;
    use bpf_common::{event_check, program::BpfEvent, test_runner::TestRunner};
    use filtering::config::Rule;
    use filtering::maps::{InterestMap, RuleMap};
    use nix::unistd::execv;
    use nix::unistd::{fork, ForkResult};
    use std::ffi::CString;
    use which::which;

    use super::*;

    /// Check we're generating the correct parent and child pid.
    /// Note: we must make sure to use the real process id (kernel space tgid)
    /// and not the thread id (kernel space pid)
    #[tokio::test]
    #[serial_test::serial]
    async fn fork_event() {
        let mut child_pid = Pid::from_raw(0);
        test_runner()
            .run(|| child_pid = fork_and_return(0))
            .await
            .expect_event_from_pid(
                child_pid,
                event_check!(
                    ProcessEvent::Fork,
                    (ppid, Pid::from_raw(std::process::id() as i32), "parent pid")
                ),
            );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn exec_event() {
        let mut child_pid = Pid::from_raw(0);
        let echo_buff = which("echo").unwrap();
        let echo_path: StringArray<NAME_MAX> = echo_buff.as_path().to_str().unwrap().into();
        test_runner()
            .run(|| {
                let mut child = std::process::Command::new("echo").spawn().unwrap();
                child_pid = Pid::from_raw(child.id() as i32);
                child.wait().unwrap();
            })
            .await
            .expect_event_from_pid(
                child_pid,
                event_check!(ProcessEvent::Exec, (filename, echo_path, "exec filename")),
            );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn exit_event() {
        let mut child_pid = Pid::from_raw(0);
        const EXIT_VALUE: u32 = 42;
        test_runner()
            .run(|| child_pid = fork_and_return(EXIT_VALUE))
            .await
            .expect_event_from_pid(
                child_pid,
                event_check!(ProcessEvent::Exit, (exit_code, EXIT_VALUE, "exit code")),
            );
    }

    /// Make sure thread exit events are filtered out
    #[tokio::test]
    #[serial_test::serial]
    async fn exit_event_no_thread() {
        let result = test_runner()
            .run(|| std::thread::spawn(|| {}).join().unwrap())
            .await;
        let found = result
            .iter()
            .any(|e: &BpfEvent<ProcessEvent>| match e.payload {
                ProcessEvent::Exit { .. } => e.pid.as_raw() as u32 == std::process::id(),
                _ => false,
            });
        assert!(
            !found,
            "found exit event thread (our pid is {})",
            std::process::id()
        );
    }

    pub fn test_runner() -> TestRunner<ProcessEvent> {
        TestRunner::with_ebpf(program)
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
            let mut bpf = load_test_program(PROCESS_MONITOR_PROBE).unwrap();
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
            let mut bpf = load_test_program(PROCESS_MONITOR_PROBE).unwrap();
            attach_tracepoint(&mut bpf, "sched_process_exec");
            let mut interest_map = InterestMap::load(&mut bpf).unwrap();
            interest_map.clear().unwrap();

            // add rule to target echo
            let image = "/usr/bin/echo";
            let rule = Rule {
                image: image.parse().unwrap(),
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
            .ok_or_else(|| ProgramError::ProgramNotFound(tp.to_string()))
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

    /// map_interest should not include thread entries because it would
    /// fill the map with useless data.
    #[test]
    #[serial_test::serial]
    fn threads_are_ignored() {
        // load ebpf and clear interest map
        let mut bpf = load_test_program(PROCESS_MONITOR_PROBE).unwrap();
        attach_fork_kprobe(&mut bpf);
        let mut interest_map = InterestMap::load(&mut bpf).unwrap();
        interest_map.clear().unwrap();

        // try spawning a new thread
        let child_thread = std::thread::spawn(nix::unistd::gettid)
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
        let mut bpf = load_test_program(PROCESS_MONITOR_PROBE).unwrap();
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
