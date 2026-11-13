//! The second decoding step: syscall records to the extension's payloads.

use next_bpf::{
    loader::ProbeSpec,
    record::{DecodeError, RecordView},
};
use next_core::probe::{Decoded, Probe};

use crate::{
    schema::{Ext, ExtPayload},
    syscalls::{self, SyscallRecord},
};

pub struct SyscallProbe;

impl Probe<Ext> for SyscallProbe {
    fn spec(&self) -> &'static ProbeSpec {
        &syscalls::SPEC
    }

    fn decode(
        &self,
        record: &RecordView<'_>,
        out: &mut Decoded<ExtPayload>,
    ) -> Result<(), DecodeError> {
        match syscalls::decode(record)? {
            SyscallRecord::Activity { total, histogram } => {
                out.payloads.push(ExtPayload::SyscallActivity {
                    total,
                    histogram: histogram.to_vec(),
                });
            }
        }
        Ok(())
    }
}
