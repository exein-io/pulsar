//! The syscalls producer, `probes/syscalls.bpf.c`: the first decoding step,
//! as next-bpf's producer modules do it for Pulsar's own probes.

use next_bpf::{
    BpfFeatures,
    loader::{Attach, ProbeSpec},
    record::{DecodeError, RecordView},
};

use self::abi::{EXAMPLE_SYSCALL_ACTIVITY, EXAMPLE_SYSCALLS_MAX, example_syscall_activity};

/// Generated from `include/example/abi.h`.
#[allow(non_camel_case_types, non_upper_case_globals, dead_code)]
mod abi {
    // The generated types refer to Pulsar's record header by name.
    use next_bpf::abi::*;

    include!(concat!(env!("OUT_DIR"), "/abi.rs"));
}

static OBJECTS: &[(BpfFeatures, &[u8])] =
    &include!(concat!(env!("OUT_DIR"), "/syscalls_objects.rs"));

pub static SPEC: ProbeSpec = ProbeSpec {
    name: "syscalls",
    objects: OBJECTS,
    programs,
};

fn programs(_: &BpfFeatures) -> Vec<Attach> {
    vec![
        Attach::RawTracePoint("sys_enter"),
        Attach::RawTracePoint("sched_process_exit"),
    ]
}

pub enum SyscallRecord {
    /// Written when the process exits.
    Activity {
        total: u64,
        /// By syscall number, for the lowest numbers.
        histogram: [u64; EXAMPLE_SYSCALLS_MAX as usize],
    },
}

pub fn decode(record: &RecordView<'_>) -> Result<SyscallRecord, DecodeError> {
    match record.kind() {
        EXAMPLE_SYSCALL_ACTIVITY => {
            let body: example_syscall_activity = record.body()?;
            Ok(SyscallRecord::Activity {
                total: body.total,
                histogram: body.histogram,
            })
        }
        kind => Err(DecodeError::UnknownKind {
            producer: record.producer(),
            kind,
        }),
    }
}
