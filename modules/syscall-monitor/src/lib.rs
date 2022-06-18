use std::{fmt, time::Duration};

use bpf_common::{
    aya::{include_bytes_aligned, maps::hash_map::HashMap, programs::TracePoint, Bpf, Pod},
    platform::SYSCALLS,
    program::{BpfContext, BpfEvent},
    time::Timestamp,
    BpfSender, Pid, Program, ProgramError, ProgramHandle, MAX_SYSCALLS,
};

const MODULE_NAME: &str = "syscall-monitor";

pub fn program(ctx: BpfContext, mut sender: impl BpfSender<ActivityT>) -> ProgramHandle {
    let mut activity_cache: std::collections::HashMap<i32, ActivityT> = Default::default();
    Program::start(
        ctx,
        MODULE_NAME,
        include_bytes_aligned!(concat!(env!("OUT_DIR"), "/probe.bpf.o")).into(),
        |bpf: &mut Bpf| {
            for (section, tp) in [
                ("raw_syscalls", "sys_enter"),
                ("sched", "sched_process_exit"),
            ] {
                let syscall_hook: &mut TracePoint = bpf
                    .program_mut(tp)
                    .ok_or_else(|| ProgramError::ProgramNotFound(tp.to_string()))?
                    .try_into()?;
                syscall_hook.load()?;
                syscall_hook.attach(section, tp)?;
            }
            let map: HashMap<_, i32, ActivityT> = HashMap::try_from(bpf.map_mut("activities")?)?;
            Ok(map)
        },
    )
    .poll(Duration::from_millis(10), move |result| {
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
        // iterate each process recorded in the syscall monitor map
        for (pid, activity) in map {
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
                timestamp: Timestamp::from(*activity.calls.iter().find(|x| x != &&0).unwrap()),
                payload: activity,
            }))
        }
    })
}

/// The data stored on the C side
#[derive(Clone, Copy, PartialEq)]
#[repr(C)]
pub struct ActivityT {
    calls: [u64; MAX_SYSCALLS],
    histogram: [u64; MAX_SYSCALLS],
}

unsafe impl Pod for ActivityT {}

impl Default for ActivityT {
    fn default() -> Self {
        Self {
            calls: [0; MAX_SYSCALLS],
            histogram: [0; MAX_SYSCALLS],
        }
    }
}

impl fmt::Display for ActivityT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut space = String::new();
        for syscall in 0..MAX_SYSCALLS {
            let n = self.histogram[syscall];
            if n > 0 || self.calls[syscall] > 0 {
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
        let _program: ProgramHandle = program(ctx.get_bpf_context(), ctx.get_sender());
        shutdown.recv().await
    }

    impl From<ActivityT> for Payload {
        fn from(data: ActivityT) -> Self {
            Payload::SyscallActivity {
                histogram: data.histogram.into(),
                calls: data.calls.into(),
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
        activity.calls[42] = 111111;
        activity.histogram[42] = 10;
        activity.calls[46] = 111119;
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
            e.pid.as_raw() as u32 == std::process::id()
                && e.payload.histogram[unlink_syscall] == 1
                && result.was_running_at(e.payload.calls[unlink_syscall].into())
        });
    }
}
