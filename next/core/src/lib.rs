//! Pulsar's userspace core: the event model, the process table, the processor
//! and the builder that wires probes, detectors and reporters together.
//!
//! ```text
//! ring (next_bpf) ─▶ ingest task ─▶ processor task ─▶ threats ─▶ reporter tasks
//!                                    decode, table, detectors
//! ```
//!
//! An extension (pulsar-enterprise, a community crate) brings its own probes,
//! payload variants, threat kinds, detectors and reporters through a
//! [`Schema`] of its own; see [`compose_payload!`] and [`compose_threat_kind!`].

pub mod daemon;
pub mod event;
pub mod payload;
pub mod probe;
pub mod processor;
pub mod seed;
pub mod table;
pub mod threat;
pub mod time;

use payload::{OssPayload, PayloadSet};
use threat::{OssThreatKind, RuleThreat, ThreatKindSet};

pub use daemon::{CoreConfig, Pulsar};

/// The types a Pulsar build works with. Every component is generic over it.
pub trait Schema: Send + Sync + 'static {
    /// Every event kind: the OSS ones and the extension's.
    type Payload: PayloadSet + From<OssPayload>;
    /// Every threat kind: the rules engine's and the extension's.
    type ThreatKind: ThreatKindSet + From<RuleThreat>;
}

/// Pulsar without extensions.
pub struct Oss;

impl Schema for Oss {
    type Payload = OssPayload;
    type ThreatKind = OssThreatKind;
}
