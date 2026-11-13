//! The extension's schema: Pulsar's payloads and threat kinds, plus its own.

use next_core::Schema;

next_core::compose_payload! {
    pub ExtPayload, kind = ExtPayloadKind {
        /// The syscalls of a process, counted until it exited.
        SyscallActivity {
            total: u64,
            /// By syscall number, for the lowest numbers.
            #[validatron(skip)]
            histogram: Vec<u64>,
        },
    }
}

next_core::compose_threat_kind! {
    pub ExtThreatKind {
        /// The model found the process anomalous.
        Ml { score: f32 },
    }
}

pub struct Ext;

impl Schema for Ext {
    type Payload = ExtPayload;
    type ThreatKind = ExtThreatKind;
}
