//! Stand-in for pulsar-enterprise's platform connector: prints every threat as
//! one JSON line in the shape the platform receives, with the attack graph
//! taken from the lineage.

use std::sync::Arc;

use next_core::{
    event::Event,
    processor::{ReportError, Reporter},
    threat::{Ancestor, ProcessSnapshot, Threat, ThreatKindSet},
};
use serde::Serialize;

use crate::schema::{Ext, ExtPayload, ExtThreatKind};

pub struct PlatformStub;

#[derive(Serialize)]
struct PlatformThreat<'a> {
    id: String,
    threat_type: &'static str,
    threat: &'a ExtThreatKind,
    detector: &'static str,
    description: &'a str,
    event: Option<&'a Event<ExtPayload>>,
    /// The subject, then its ancestors, nearest first.
    attack_graph: Vec<GraphNode<'a>>,
}

#[derive(Serialize)]
struct GraphNode<'a> {
    pid: Option<u32>,
    image: Option<&'a str>,
    /// Events the platform would receive with the node.
    events: usize,
}

impl GraphNode<'_> {
    fn of(process: &ProcessSnapshot, events: usize) -> GraphNode<'_> {
        GraphNode {
            pid: process.pid,
            image: process.image.as_ref().map(|image| image.value.as_str()),
            events,
        }
    }
}

impl Reporter<Ext> for PlatformStub {
    fn name(&self) -> &'static str {
        "platform-stub"
    }

    async fn report(&mut self, threat: Arc<Threat<Ext>>) -> Result<(), ReportError> {
        let mut attack_graph = vec![GraphNode::of(&threat.subject, 0)];
        attack_graph.extend(threat.lineage.iter().map(|ancestor| match ancestor {
            Ancestor::Known {
                process, window, ..
            } => GraphNode::of(process, window.len()),
            Ancestor::Unknown { pid } => GraphNode {
                pid: *pid,
                image: None,
                events: 0,
            },
        }));
        let message = PlatformThreat {
            id: threat.id.to_string(),
            threat_type: threat.kind.name(),
            threat: &threat.kind,
            detector: threat.detector,
            description: &threat.description,
            event: threat.event.as_deref(),
            attack_graph,
        };
        println!("{}", serde_json::to_string(&message)?);
        Ok(())
    }
}
