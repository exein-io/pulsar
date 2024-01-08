use std::{fs, os::unix::fs::MetadataExt};

use anyhow::Context;
use bpf_common::{
    aya::maps::HashMap,
    containers::ContainerError,
    ebpf_program,
    parsing::{BufferIndex, IndexError},
    program::BpfContext,
    BpfSender, Pid, Program, ProgramBuilder, ProgramError,
};
use pulsar_core::event::Namespaces;
use thiserror::Error;
use which::which;

const MODULE_NAME: &str = "process-monitor";

pub async fn program(
    ctx: BpfContext,
    sender: impl BpfSender<ProcessEvent>,
) -> Result<Program, ProgramError> {
    let binary = ebpf_program!(&ctx, "probes");
    let mut program = ProgramBuilder::new(ctx, MODULE_NAME, binary)
        .raw_tracepoint("sched_process_exec")
        .raw_tracepoint("sched_process_exit")
        .raw_tracepoint("sched_process_fork")
        .raw_tracepoint("sched_switch")
        .raw_tracepoint("cgroup_mkdir")
        .raw_tracepoint("cgroup_rmdir")
        .raw_tracepoint("cgroup_attach_task")
        .start()
        .await?;

    let mut container_runtimes_map: HashMap<_, u64, u8> = program
        .bpf()
        .map_mut("container_runtimes_map")
        .unwrap()
        .try_into()?;
    for container_runtime in ["crun", "containerd-shim-runc-v2", "runc", "youki"] {
        if let Ok(runtime_path) = which(container_runtime) {
            let ino = fs::metadata(&runtime_path)
                .map_err(|e| ProgramError::InodeError {
                    path: runtime_path,
                    io_error: Box::new(e),
                })?
                .ino();
            container_runtimes_map.insert(ino, 0, 0)?;
        }
    }

    program
        .read_events("map_output_process_event", sender)
        .await?;
    Ok(program)
}

#[derive(Error, Debug)]
pub enum ProcessEventError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Container(#[from] ContainerError),
    #[error("container not found for process {0}")]
    ContainerNotFound(Pid),
}

// The events sent from eBPF to userspace must be byte by byte
// re-interpretable as Rust types. So pointers to the heap are
// not allowed.
#[derive(Debug)]
#[repr(C)]
pub enum ProcessEvent {
    Fork {
        ppid: Pid,
        namespaces: Namespaces,
        is_new_container: bool,
    },
    Exec {
        filename: BufferIndex<str>,
        argc: u32,
        argv: BufferIndex<str>, // 0 separated strings
        namespaces: Namespaces,
        is_new_container: bool,
    },
    Exit {
        exit_code: u32,
    },
    ChangeParent {
        ppid: Pid,
    },
    CgroupMkdir {
        path: BufferIndex<str>,
        id: u64,
    },
    CgroupRmdir {
        path: BufferIndex<str>,
        id: u64,
    },
    CgroupAttach {
        pid: Pid,
        path: BufferIndex<str>,
        id: u64,
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
    use bpf_common::{program::BpfEvent, BpfSenderWrapper};
    use pulsar_core::pdk::{
        process_tracker::TrackerUpdate, CleanExit, IntoPayload, ModuleContext, ModuleError,
        Payload, PulsarModule, ShutdownSignal, Version,
    };
    use tokio::sync::mpsc;

    pub fn module() -> PulsarModule {
        PulsarModule::new(
            MODULE_NAME,
            Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            true,
            process_monitor_task,
        )
    }

    async fn process_monitor_task(
        ctx: ModuleContext,
        mut shutdown: ShutdownSignal,
    ) -> Result<CleanExit, ModuleError> {
        let rx_config = ctx.get_config();
        let filtering_config: bpf_filtering::config::Config = rx_config.read()?;
        let process_tracker = ctx.get_process_tracker();
        let (tx_processes, mut rx_processes) = mpsc::unbounded_channel();
        let mut program = program(
            ctx.get_bpf_context(),
            // When generating events we must update process_tracker.
            // We do this by wrapping the pulsar sender and calling this closure on every event.
            BpfSenderWrapper::new(ctx.get_sender(), move |event: &BpfEvent<ProcessEvent>| {
                let _ = tx_processes.send(match event.payload {
                    ProcessEvent::Fork {
                        ppid,
                        namespaces,
                        is_new_container,
                    } => TrackerUpdate::Fork {
                        pid: event.pid,
                        ppid,
                        timestamp: event.timestamp,
                        namespaces,
                        is_new_container,
                    },
                    ProcessEvent::Exec {
                        ref filename,
                        argc,
                        ref argv,
                        namespaces,
                        is_new_container,
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
                            namespaces,
                            is_new_container,
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
                    _ => return,
                });
            }),
        )
        .await?;

        bpf_filtering::initializer::setup_events_filter(
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
        type Error = ProcessEventError;
        fn try_into_payload(event: BpfEvent<ProcessEvent>) -> Result<Payload, ProcessEventError> {
            let BpfEvent {
                payload, buffer, ..
            } = event;
            Ok(match payload {
                ProcessEvent::Fork { ppid, .. } => Payload::Fork {
                    ppid: ppid.as_raw(),
                },
                ProcessEvent::Exec {
                    filename,
                    argc,
                    argv,
                    ..
                } => Payload::Exec {
                    filename: filename.string(&buffer)?,
                    argc: argc as usize,
                    argv: extract_parameters(argv.bytes(&buffer)?).into(),
                },
                ProcessEvent::Exit { exit_code } => Payload::Exit { exit_code },
                ProcessEvent::ChangeParent { ppid } => Payload::ChangeParent {
                    ppid: ppid.as_raw(),
                },
                ProcessEvent::CgroupMkdir { path, id } => Payload::CgroupCreated {
                    cgroup_path: path.string(&buffer)?,
                    cgroup_id: id,
                },
                ProcessEvent::CgroupRmdir { path, id } => Payload::CgroupDeleted {
                    cgroup_path: path.string(&buffer)?,
                    cgroup_id: id,
                },
                ProcessEvent::CgroupAttach { pid, path, id } => Payload::CgroupAttach {
                    cgroup_path: path.string(&buffer)?,
                    cgroup_id: id,
                    attached_pid: pid.as_raw(),
                },
            })
        }
    }
}

#[cfg(feature = "test-suite")]
pub mod test_suite {
    use bpf_common::test_runner::{TestCase, TestReport, TestSuite};
    use bpf_common::test_utils::cgroup::{fork_in_temp_cgroup, temp_cgroup};
    use bpf_common::test_utils::{find_executable, random_name_with_prefix};
    use bpf_common::{event_check, program::BpfEvent, test_runner::TestRunner};
    use nix::libc::{prctl, PR_SET_CHILD_SUBREAPER};
    use nix::unistd::{fork, ForkResult};
    use std::fs;
    use std::process::exit;
    use std::thread::sleep;
    use std::time::Duration;

    use super::*;

    pub fn tests() -> TestSuite {
        TestSuite {
            name: "process-monitor",
            tests: vec![
                fork_event(),
                exec_event(),
                relative_exec_event(),
                exit_event(),
                exit_event_no_thread(),
                parent_change(),
                cgroup_mkdir(),
                cgroup_rmdir(),
                cgroup_attach(),
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
            let echo_buff = find_executable("echo");
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

    fn relative_exec_event() -> TestCase {
        TestCase::new("relative_exec_event", async {
            let mut child_pid = Pid::from_raw(0);
            let echo_buff = find_executable("echo").canonicalize().unwrap();
            let echo_path = echo_buff.as_path().to_str().unwrap().to_string();
            test_runner()
                .run(|| {
                    let mut child = std::process::Command::new("./echo")
                        .current_dir(echo_buff.as_path().parent().unwrap())
                        .arg("-n")
                        .spawn()
                        .unwrap();
                    child_pid = Pid::from_raw(child.id() as i32);
                    child.wait().unwrap();
                })
                .await
                .expect_event_from_pid(
                    child_pid,
                    event_check!(ProcessEvent::Exec, (filename, echo_path, "exec filename")),
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

    fn cgroup_mkdir() -> TestCase {
        TestCase::new("cgroup_mkdir", async {
            let name = random_name_with_prefix("pulsar_cgroup_mkdir");
            let path = format!("/{name}");
            let mut id = 0;

            test_runner()
                .run(|| id = temp_cgroup(name))
                .await
                .expect_event(event_check!(
                    ProcessEvent::CgroupMkdir,
                    (id, id, "cgroup id"),
                    (path, path, "cgroup path")
                ))
                .report()
        })
    }

    fn cgroup_rmdir() -> TestCase {
        TestCase::new("cgroup_rmdir", async {
            let name = random_name_with_prefix("pulsar_cgroup_rmdir");
            let cg_path = format!("/{name}");
            let mut id = 0;

            test_runner()
                .run(|| id = temp_cgroup(name))
                .await
                .expect_event(event_check!(
                    ProcessEvent::CgroupRmdir,
                    (id, id, "cgroup id"),
                    (path, cg_path, "cgroup path")
                ))
                .report()
        })
    }

    fn cgroup_attach() -> TestCase {
        TestCase::new("cgroup_attach", async {
            let name = random_name_with_prefix("pulsar_cgroup_attach");
            let cg_path = format!("/{name}");
            let mut id = 0;
            let mut child_pid = Pid::from_raw(0);

            test_runner()
                .run(|| (child_pid, id) = fork_in_temp_cgroup(&name))
                .await
                .expect_event(event_check!(
                    ProcessEvent::CgroupAttach,
                    (id, id, "cgroup id"),
                    (pid, child_pid, "attached process"),
                    (path, cg_path, "cgroup path")
                ))
                .report()
        })
    }
}
