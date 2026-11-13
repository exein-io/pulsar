//! Threats: what detectors report and reporters receive.

use std::{fmt, sync::Arc, time::SystemTime};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    Schema,
    event::{Container, Event},
    payload::{Argv, Text},
};

/// A threat kind enum, composed by [`compose_threat_kind!`](crate::compose_threat_kind).
pub trait ThreatKindSet: Serialize + Clone + fmt::Debug + Send + Sync + 'static {
    fn name(&self) -> &'static str;
}

/// Declares a threat kind enum with the OSS kind, `Rule`, followed by the
/// given ones:
///
/// ```ignore
/// next_core::compose_threat_kind! { pub ExtThreatKind { Ml { score: f32 } } }
/// ```
///
/// The enum derives `serde::Serialize`, so the calling crate depends on `serde`.
#[macro_export]
macro_rules! compose_threat_kind {
    ($(#[$meta:meta])* $vis:vis $name:ident {
        $( $(#[$vmeta:meta])* $var:ident { $( $field:ident : $fty:ty ),* $(,)? } ),* $(,)?
    }) => {
        $(#[$meta])*
        #[derive(Clone, Debug, serde::Serialize)]
        $vis enum $name {
            Rule($crate::threat::RuleThreat),
            $( $(#[$vmeta])* $var { $( $field : $fty ),* }, )*
        }

        impl $crate::threat::ThreatKindSet for $name {
            fn name(&self) -> &'static str {
                match self {
                    Self::Rule(_) => "Rule",
                    $( Self::$var { .. } => stringify!($var), )*
                }
            }
        }

        impl From<$crate::threat::RuleThreat> for $name {
            fn from(threat: $crate::threat::RuleThreat) -> Self {
                Self::Rule(threat)
            }
        }
    };
}

compose_threat_kind! {
    /// The threat kinds of Pulsar's own detectors.
    pub OssThreatKind {}
}

/// A rule of the rules engine matched.
#[derive(Clone, Debug, Serialize)]
pub struct RuleThreat {
    pub rule: String,
    pub category: Category,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    CommandAndControl,
    CredentialAccess,
    DefenseEvasion,
    Discovery,
    Execution,
    Exfiltration,
    Generic,
    Impact,
    InitialAccess,
    LateralMovement,
    Persistence,
    PrivilegeEscalation,
    Reconnaissance,
    ResourceDevelopment,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// A process as the process table knew it. Every field can be unknown.
/// Under review, see [`table`](crate::table).
#[derive(Clone, Debug, Default, Serialize)]
pub struct ProcessSnapshot {
    pub pid: Option<u32>,
    pub start_time: Option<SystemTime>,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub image: Option<Text>,
    pub argv: Option<Argv>,
    pub container: Option<Container>,
    pub exited: bool,
}

/// An ancestor of the threat's subject, nearest first. Under review, see [`table`](crate::table).
#[derive(Clone, Debug, Serialize)]
#[serde(bound = "P: Serialize")]
pub enum Ancestor<P> {
    Known {
        process: ProcessSnapshot,
        /// Its last events before it forked the next process in the lineage.
        window: Vec<Arc<Event<P>>>,
        /// Records were lost while the window was filled.
        window_spans_gap: bool,
    },
    /// Records that would name it were lost.
    Unknown { pid: Option<u32> },
}

#[derive(Serialize)]
#[serde(bound = "")]
pub struct Threat<S: Schema> {
    /// UUID v7: sorts by creation time.
    pub id: Uuid,
    pub detector: &'static str,
    pub kind: S::ThreatKind,
    pub description: String,
    /// The event that triggered it; `None` for detections over a window.
    pub event: Option<Arc<Event<S::Payload>>>,
    /// Under review, see [`table`](crate::table).
    pub subject: ProcessSnapshot,
    /// Under review, see [`table`](crate::table).
    pub lineage: Vec<Ancestor<S::Payload>>,
    pub timestamp: SystemTime,
}
