use anyhow::Context;
use bpf_common::{
    ebpf_program, parsing::BufferIndex, program::BpfContext, BpfSender, Pid, Program,
    ProgramBuilder, ProgramError,
};
mod filtering;

const MODULE_NAME: &str = "process-monitor";

pub async fn program(
    ctx: BpfContext,
    sender: impl BpfSender<ProcessEvent>,
) -> Result<Program, ProgramError> {
    let binary = ebpf_program!(&ctx);
    let mut program = ProgramBuilder::new(ctx, MODULE_NAME, binary)
        .raw_tracepoint("sched_process_exec")
        .raw_tracepoint("sched_process_exit")
        .raw_tracepoint("sched_process_fork")
        .raw_tracepoint("sched_switch")
        .start()
        .await?;
    program.read_events("events", sender).await?;
    Ok(program)
}

// The events sent from eBPF to userspace must be byte by byte
// re-interpretable as Rust types. So pointers to the heap are
// not allowed.
#[derive(Debug)]
#[repr(C)]
pub enum ProcessEvent {
    Fork {
        ppid: Pid,
    },
    Exec {
        filename: BufferIndex<str>,
        argc: u32,
        argv: BufferIndex<str>, // 0 separated strings
    },
    Exit {
        exit_code: u32,
    },
    ChangeParent {
        ppid: Pid,
    },
}

fn extract_parameters(argv: &[u8]) -> Vec<String> {
    // Ignore the last byte as it's always a 0. Not doing this would
    // produce a trailing "" argument.
    let len = if argv.last() == Some(&0) {
        argv.len() - 1
    } else {
        argv.len()
    };
    argv[..len]
        .split(|x| *x == 0)
        .map(String::from_utf8_lossy)
        .map(String::from)
        .collect()
}

pub mod pulsar {
    use super::*;
    use bpf_common::{parsing::IndexError, program::BpfEvent, BpfSenderWrapper};
    use pulsar_core::pdk::{
        process_tracker::TrackerUpdate, CleanExit, IntoPayload, ModuleContext, ModuleError,
        Payload, PulsarModule, ShutdownSignal, Version,
    };
    use tokio::sync::mpsc;

    pub fn module() -> PulsarModule {
        PulsarModule::new(
            MODULE_NAME,
            Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            process_monitor_task,
        )
    }

    async fn process_monitor_task(
        ctx: ModuleContext,
        mut shutdown: ShutdownSignal,
    ) -> Result<CleanExit, ModuleError> {
        let rx_config = ctx.get_config();
        let filtering_config: filtering::config::Config = rx_config.read()?;
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
                    ProcessEvent::Exec {
                        ref filename,
                        argc,
                        ref argv,
                    } => {
                        let argv =
                            extract_parameters(argv.bytes(&event.buffer).unwrap_or_else(|err| {
                                log::error!("Error getting program arguments: {}", err);
                                &[]
                            }));
                        if argv.len() != argc as usize {
                            log::warn!(
                                "argc ({}) doens't match argv ({:?}) for {}",
                                argc,
                                argv,
                                event.pid
                            )
                        }
                        TrackerUpdate::Exec {
                            pid: event.pid,
                            // ignoring this error since it will be catched in IntoPayload
                            image: filename.string(&event.buffer).unwrap_or_default(),
                            timestamp: event.timestamp,
                            argv,
                        }
                    }
                    ProcessEvent::Exit { .. } => TrackerUpdate::Exit {
                        pid: event.pid,
                        timestamp: event.timestamp,
                    },
                    ProcessEvent::ChangeParent { ppid } => TrackerUpdate::SetNewParent {
                        pid: event.pid,
                        ppid,
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
        .await
        .context("Error initializing process filtering")?;

        // rx_processes will first be used during initialization,
        // than it will be used to keep the process tracker updated

        loop {
            tokio::select! {
                r = shutdown.recv() => return r,
                Some(msg) = rx_processes.recv() => process_tracker.update(msg),
            }
        }
    }

    impl IntoPayload for ProcessEvent {
        type Error = IndexError;
        fn try_into_payload(event: BpfEvent<ProcessEvent>) -> Result<Payload, IndexError> {
            let BpfEvent {
                payload, buffer, ..
            } = event;
            Ok(match payload {
                ProcessEvent::Fork { ppid } => Payload::Fork {
                    ppid: ppid.as_raw(),
                },
                ProcessEvent::Exec {
                    filename,
                    argc,
                    argv,
                } => Payload::Exec {
                    filename: filename.string(&buffer)?,
                    argc: argc as usize,
                    argv: extract_parameters(argv.bytes(&buffer)?).into(),
                },
                ProcessEvent::Exit { exit_code } => Payload::Exit { exit_code },
                ProcessEvent::ChangeParent { ppid } => Payload::ChangeParent {
                    ppid: ppid.as_raw(),
                },
            })
        }
    }
}

#[cfg(feature = "test-suite")]
pub mod test_suite {
    use crate::filtering::maps::PolicyDecision;
    use bpf_common::aya::programs::RawTracePoint;
    use bpf_common::aya::{Bpf, BpfLoader};
    use bpf_common::test_runner::{TestCase, TestReport, TestSuite};
    use bpf_common::{event_check, program::BpfEvent, test_runner::TestRunner};
    use filtering::config::Rule;
    use filtering::maps::{InterestMap, RuleMap};
    use nix::libc::{prctl, PR_SET_CHILD_SUBREAPER};
    use nix::unistd::execv;
    use nix::unistd::{fork, ForkResult};
    use std::ffi::CString;
    use std::fs;
    use std::process::exit;
    use std::thread::sleep;
    use std::time::Duration;
    use which::which;

    use super::*;

    pub fn tests() -> TestSuite {
        TestSuite {
            name: "process-monitor",
            tests: vec![
                fork_event(),
                exec_event(),
                exit_event(),
                exit_event_no_thread(),
                inherit_policy(),
                exec_updates_interest(),
                threads_are_ignored(),
                exit_cleans_up_resources(),
                parent_change(),
            ],
        }
    }

    /// Check we're generating the correct parent and child pid.
    /// Note: we must make sure to use the real process id (kernel space tgid)
    /// and not the thread id (kernel space pid)
    fn fork_event() -> TestCase {
        TestCase::new("fork_event", async {
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
                )
                .report()
        })
    }

    fn exec_event() -> TestCase {
        TestCase::new("exec_event", async {
            let mut child_pid = Pid::from_raw(0);
            let echo_buff = which("echo").unwrap();
            let echo_path = echo_buff.as_path().to_str().unwrap().to_string();
            test_runner()
                .run(|| {
                    let mut child = std::process::Command::new("echo")
                        .arg("-n")
                        .spawn()
                        .unwrap();
                    child_pid = Pid::from_raw(child.id() as i32);
                    child.wait().unwrap();
                })
                .await
                .expect_event_from_pid(
                    child_pid,
                    event_check!(
                        ProcessEvent::Exec,
                        (filename, echo_path, "exec filename"),
                        (argc, 2, "number of arguments"),
                        (argv, String::from("echo\0-n\0"), "arguments")
                    ),
                )
                .report()
        })
    }

    fn exit_event() -> TestCase {
        TestCase::new("exit_event", async {
            let mut child_pid = Pid::from_raw(0);
            const EXIT_VALUE: i32 = 42;
            test_runner()
                .run(|| child_pid = fork_and_return(EXIT_VALUE))
                .await
                .expect_event_from_pid(
                    child_pid,
                    event_check!(
                        ProcessEvent::Exit,
                        (exit_code, EXIT_VALUE as u32, "exit code")
                    ),
                )
                .report()
        })
    }

    /// Make sure thread exit events are filtered out
    fn exit_event_no_thread() -> TestCase {
        TestCase::new("exit_event_no_thread", async {
            let result = test_runner()
                .run(|| std::thread::spawn(|| {}).join().unwrap())
                .await;
            let found = result
                .events
                .iter()
                .any(|e: &BpfEvent<ProcessEvent>| match e.payload {
                    ProcessEvent::Exit { .. } => e.pid.as_raw() as u32 == std::process::id(),
                    _ => false,
                });
            if found {
                TestReport {
                    success: false,
                    lines: vec![format!(
                        "found exit event thread (our pid is {})",
                        std::process::id()
                    )],
                }
            } else {
                TestReport {
                    success: true,
                    lines: Vec::new(),
                }
            }
        })
    }

    pub fn test_runner() -> TestRunner<ProcessEvent> {
        TestRunner::with_ebpf(program)
    }

    /// Fork current project and store child pid inside child_pid
    pub fn fork_and_return(exit_code: i32) -> Pid {
        fork_and_run(move || exit(exit_code))
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
                let child_pid = fork_and_return(0).as_raw();

                // make sure the eBPF fork code expanded interest to the child
                let expected_interest = PolicyDecision {
                    interesting: interest_in_child,
                    children_interesting: interest_in_child,
                }
                .as_raw();
                let actual_interest = interest_map.0.get(&child_pid, 0).ok();
                if Some(expected_interest) != actual_interest {
                    report.lines.push(format!(
                        "expecting {child_pid}={expected_interest} (was {actual_interest:?})",
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
            for (is_target, with_children) in
                [(true, true), (true, false), (false, true), (false, false)]
            {
                // load ebpf and clear interest map
                let mut bpf = load_ebpf();
                attach_raw_tracepoint(&mut bpf, "sched_process_exec");
                let mut interest_map = InterestMap::load(&mut bpf).unwrap();
                interest_map.clear().unwrap();

                // add rule to target echo
                let image = which("echo").unwrap().to_string_lossy().to_string();
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
                    let child_pid = fork_and_run(|| {
                        // before calling exec, we want to update our interest
                        let old_value = PolicyDecision {
                            interesting: !is_target,
                            children_interesting: old_with_children,
                        }
                        .as_raw();
                        let pid = std::process::id() as i32;
                        interest_map_ref.0.insert(pid, old_value, 0).unwrap();
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
                        interesting: is_target,
                        children_interesting: if with_children {
                            is_target
                        } else {
                            old_with_children
                        },
                    }
                    .as_raw();
                    let actual_interest = interest_map.0.get(&child_pid, 0).unwrap();
                    if expected_interest != actual_interest {
                        report
                        .lines
                        .push(format!("is_target={is_target} with_children={with_children} old_with_children={old_with_children}"));
                        report
                            .lines
                            .push(format!("expecting {child_pid}={expected_interest}"));
                        report.success = false;
                    }
                }
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
            let mut interest_map = InterestMap::load(&mut bpf).unwrap();
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
            if interest_map.0.get(&child_thread, 0).is_ok() {
                report.success = false;
                report
                    .lines
                    .push("unexpected entry for child thread".to_string())
            }
            // make sure we've not overridden the parent interest
            // with the child one.
            if interest_map.0.get(&our_pid, 0).is_ok() {
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
            let mut interest_map = InterestMap::load(&mut bpf).unwrap();
            interest_map.clear().unwrap();

            let interest_map_ref = &mut interest_map;
            let child_pid = fork_and_run(move || {
                let pid = std::process::id() as i32;
                interest_map_ref.0.insert(pid, 0, 0).unwrap();
                exit(0);
            })
            .as_raw();

            // make sure exit hook deleted it
            TestReport {
                success: interest_map.0.get(&child_pid, 0).is_err(),
                lines: vec![format!(
                    "exit should have deleted PID {child_pid} from map_interest"
                )],
            }
        })
    }

    /// When the parent of a process dies, it should be re-parented to the closest
    /// subreaper, or pid 1
    fn parent_change() -> TestCase {
        TestCase::new("parent_change", async {
            // Assuming the test-suite is running as process A:
            // - We set ourself as sub-reaper
            // - We spawn an intermediate process B
            // - B spawns a process C
            // - C stays alive (it outlives the test)
            // - B saves the pid of process C to a file
            // - B exits
            // - We read the pid of C from the file
            // - We make sure the new parent of C is A
            // We expect a parent change event from C with a new parent
            let pid_a = Pid::from_raw(std::process::id() as i32);
            let mut pid_c = Pid::from_raw(0);
            let shared_file = std::env::temp_dir().join("process_c_pid.txt");
            _ = fs::remove_file(&shared_file);
            test_runner()
                .run(|| {
                    unsafe { prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
                    fork_and_run(|| {
                        match unsafe { fork() }.unwrap() {
                            ForkResult::Child => {
                                sleep(Duration::from_secs(2));
                                exit(0)
                            }
                            ForkResult::Parent { child: pid_c } => {
                                _ = fs::write(&shared_file, pid_c.as_raw().to_le_bytes());
                                exit(0);
                            }
                        };
                    });
                    pid_c = Pid::from_raw(i32::from_le_bytes(
                        fs::read(&shared_file).unwrap().try_into().unwrap(),
                    ));
                })
                .await
                .expect_event_from_pid(
                    pid_c,
                    event_check!(ProcessEvent::ChangeParent, (ppid, pid_a, "parent pid")),
                )
                .report()
        })
    }

    fn load_ebpf() -> Bpf {
        let ctx = BpfContext::new(
            bpf_common::program::Pinning::Disabled,
            bpf_common::program::PERF_PAGES_DEFAULT,
            bpf_common::program::BpfLogLevel::Debug,
            false,
        )
        .unwrap();
        const PIN_PATH: &str = "/sys/fs/bpf/process-monitor-test";
        let _ = std::fs::create_dir(PIN_PATH);
        let bpf = BpfLoader::new()
            .map_pin_path(PIN_PATH)
            .load(ebpf_program!(&ctx))
            .unwrap();
        bpf
    }
}
