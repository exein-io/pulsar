mod filtering_policy;
use std::fmt;

use bpf_common::{
    aya::include_bytes_aligned, parsing::StringArray, program::BpfContext, BpfSender, Pid, Program,
    ProgramBuilder, ProgramError,
};
pub use filtering_policy::{FilteringPolicy, PidRule, Rule};

const MODULE_NAME: &str = "process-monitor";

pub async fn program(
    ctx: BpfContext,
    sender: impl BpfSender<ProcessEvent>,
) -> Result<Program, ProgramError> {
    let program = ProgramBuilder::new(ctx, MODULE_NAME, process_monitor_ebpf())
        .tracepoint("sched", "sched_process_exec")
        .tracepoint("sched", "sched_process_exit")
        .kprobe("wake_up_new_task")
        .start()
        .await?;
    program.read_events("events", sender).await?;
    Ok(program)
}

fn process_monitor_ebpf() -> Vec<u8> {
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/probe.bpf.o")).into()
}

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
    use bpf_common::{program::BpfEvent, BpfSenderWrapper, Pid};
    use pulsar_core::pdk::{
        CleanExit, ConfigError, ModuleConfig, ModuleContext, ModuleError, Payload, PulsarModule,
        ShutdownSignal, Version,
    };

    pub fn module() -> PulsarModule {
        PulsarModule::new(MODULE_NAME, Version::new(0, 0, 1), process_monitor_task)
    }

    async fn process_monitor_task(
        ctx: ModuleContext,
        mut shutdown: ShutdownSignal,
    ) -> Result<CleanExit, ModuleError> {
        let rx_config = ctx.get_cfg::<FilteringPolicy>();
        let _policy = rx_config.borrow().as_ref().unwrap().clone();
        let process_tracker = ctx.get_process_tracker();
        let sender = ctx.get_sender();
        // When generating events we must update process_tracker.
        // We do this by wrapping the pulsar sender and calling this closure on every event.
        let sender =
            BpfSenderWrapper::new(sender, move |event: &BpfEvent<ProcessEvent>| {
                match event.payload {
                    ProcessEvent::Fork { ppid } => {
                        process_tracker.fork(ppid, event.pid, event.timestamp)
                    }
                    ProcessEvent::Exec { ref filename } => {
                        process_tracker.exec(event.pid, filename.to_string(), event.timestamp)
                    }
                    ProcessEvent::Exit { .. } => process_tracker.exit(event.pid, event.timestamp),
                }
            });
        let _program = program(ctx.get_bpf_context(), sender);
        shutdown.recv().await
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

    /// Extract FilteringPolicy from configuration file
    impl TryFrom<&ModuleConfig> for FilteringPolicy {
        type Error = ConfigError;

        fn try_from(config: &ModuleConfig) -> Result<Self, Self::Error> {
            let mut pid_targets = Vec::new();
            pid_targets.extend(config.get_list("pid_targets")?.iter().map(|pid| PidRule {
                pid: Pid::from_raw(*pid),
                with_children: false,
            }));
            pid_targets.extend(config.get_list("pid_targets_children")?.iter().map(|pid| {
                PidRule {
                    pid: Pid::from_raw(*pid),
                    with_children: false,
                }
            }));
            let mut targets = Vec::new();
            targets.extend(config.get_list("targets")?.into_iter().map(|image| Rule {
                image,
                with_children: false,
            }));
            targets.extend(
                config
                    .get_list("targets_children")?
                    .into_iter()
                    .map(|image| Rule {
                        image,
                        with_children: true,
                    }),
            );
            let mut whitelist = Vec::new();
            whitelist.extend(config.get_list("whitelist")?.into_iter().map(|image| Rule {
                image,
                with_children: false,
            }));
            whitelist.extend(
                config
                    .get_list("whitelist_children")?
                    .into_iter()
                    .map(|image| Rule {
                        image,
                        with_children: true,
                    }),
            );

            Ok(FilteringPolicy {
                pid_targets,
                targets,
                whitelist,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use bpf_common::{event_check, program::BpfEvent, test_runner::TestRunner};
    use nix::unistd::{fork, ForkResult};

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
        test_runner()
            .run(|| {
                let mut child = std::process::Command::new("echo").spawn().unwrap();
                child_pid = Pid::from_raw(child.id() as i32);
                child.wait().unwrap();
            })
            .await
            .expect_event_from_pid(
                child_pid,
                event_check!(
                    ProcessEvent::Exec,
                    (filename, "/usr/bin/echo".into(), "exec filename")
                ),
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
}
