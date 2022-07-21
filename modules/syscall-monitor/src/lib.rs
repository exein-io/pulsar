use std::{collections::HashSet, fmt, time::Duration};

use bpf_common::{
    aya::{include_bytes_aligned, Pod},
    platform::SYSCALLS,
    program::{BpfContext, BpfEvent},
    time::Timestamp,
    BpfSender, Pid, Program, ProgramBuilder, ProgramError, MAX_SYSCALLS,
};

const MODULE_NAME: &str = "syscall-monitor";

pub async fn program(
    ctx: BpfContext,
    mut sender: impl BpfSender<ActivityT>,
) -> Result<Program, ProgramError> {
    let mut activity_cache: std::collections::HashMap<i32, ActivityT> = Default::default();
    let program = ProgramBuilder::new(
        ctx,
        MODULE_NAME,
        include_bytes_aligned!(concat!(env!("OUT_DIR"), "/probe.bpf.o")).into(),
    )
    .tracepoint("raw_syscalls", "sys_enter")
    .tracepoint("sched", "sched_process_exit")
    .start()
    .await?;
    program
        .poll("activities", Duration::from_millis(10), move |result| {
            let map = match result {
                Ok(map) => map,
                Err(e) => return sender.send(Err(e)),
            };
            // map is an iterator over Result<item, MapError>
            let map = map.iter().flat_map(|item| match item {
                Err(e) => {
                    log::warn!("Error reading map: {}", e);
                    None
                }
                Ok(v) => Some(v),
            });
            // set of processes contained in the activities map
            let mut running_processes = HashSet::new();
            // iterate each process recorded in the syscall monitor map
            for (pid, activity) in map {
                running_processes.insert(pid);
                // check previous state
                if let Some(old_activity) = activity_cache.get(&pid) {
                    if *old_activity == activity {
                        continue;
                    }
                }

                // keep track of the state of this process
                activity_cache.insert(pid, activity);

                sender.send(Ok(BpfEvent {
                    pid: Pid::from_raw(pid),
                    timestamp: Timestamp::now(),
                    payload: activity,
                }))
            }
            // remove exited processes to avoid a memory leak.
            activity_cache.retain(|pid, _| running_processes.contains(pid));
        })
        .await?;
    Ok(program)
}

/// The data stored on the C side
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ActivityT {
    histogram: [u64; MAX_SYSCALLS],
}

unsafe impl Pod for ActivityT {}

impl Default for ActivityT {
    fn default() -> Self {
        Self {
            histogram: [0; MAX_SYSCALLS],
        }
    }
}

impl fmt::Display for ActivityT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut space = String::new();
        for syscall in 0..MAX_SYSCALLS {
            let n = self.histogram[syscall];
            if n > 0 {
                let syscall_name = SYSCALLS.get(&syscall).unwrap_or(&"??");
                write!(f, "{space}{syscall_name}x{n}")?;
                space = " ".to_string();
            }
        }
        Ok(())
    }
}

pub mod pulsar {
    use super::*;
    use pulsar_core::pdk::{
        CleanExit, ModuleContext, ModuleError, Payload, PulsarModule, ShutdownSignal, Version,
    };

    pub fn module() -> PulsarModule {
        PulsarModule::new(MODULE_NAME, Version::new(0, 0, 1), syscall_monitor_task)
    }

    async fn syscall_monitor_task(
        ctx: ModuleContext,
        mut shutdown: ShutdownSignal,
    ) -> Result<CleanExit, ModuleError> {
        let _program = program(ctx.get_bpf_context(), ctx.get_sender()).await?;
        shutdown.recv().await
    }

    impl From<ActivityT> for Payload {
        fn from(data: ActivityT) -> Self {
            Payload::SyscallActivity {
                histogram: data.histogram.into(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bpf_common::test_runner::TestRunner;

    #[test]
    fn activity_display() {
        let mut activity = ActivityT::default();
        assert_eq!(activity.to_string(), "");
        activity.histogram[42] = 10;
        activity.histogram[46] = 9;
        assert_eq!(
            activity.to_string(),
            format!(
                "{}x10 {}x9",
                bpf_common::platform::SYSCALLS.get(&42).unwrap(),
                bpf_common::platform::SYSCALLS.get(&46).unwrap()
            )
        );
    }

    #[tokio::test]
    async fn syscalls_generated() {
        let result = TestRunner::with_ebpf(program)
            .run(|| {
                let _ = std::fs::remove_file("/tmp/test_activity");
            })
            .await;
        let unlink_syscall: usize = *SYSCALLS.iter().find(|(_, v)| **v == "UNLINK").unwrap().0;
        result.expect(|e: &BpfEvent<ActivityT>| {
            e.pid.as_raw() as u32 == std::process::id() && e.payload.histogram[unlink_syscall] == 1
        });
    }
}
