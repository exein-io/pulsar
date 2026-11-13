//! Stand-in for pulsar-enterprise's anomaly detection. The model is replaced by
//! a trivial score; what it shows is a detector on an extension kind that
//! reads the process table and reports an extension threat kind.

use std::sync::Arc;

use next_core::{
    event::Event,
    payload::{PayloadKind, PayloadSet},
    processor::{DetectCtx, Detector, Interest},
};

use crate::schema::{Ext, ExtPayload, ExtPayloadKind, ExtThreatKind};

/// Scores at or above it are reported.
const THRESHOLD: f32 = 0.4;

pub struct AnomalyStub;

impl Detector<Ext> for AnomalyStub {
    fn name(&self) -> &'static str {
        "anomaly-stub"
    }

    fn interest(&self) -> Interest<ExtPayloadKind> {
        Interest::Kinds(vec![ExtPayloadKind::SyscallActivity])
    }

    fn on_event(&mut self, event: &Arc<Event<ExtPayload>>, cx: &mut DetectCtx<'_, Ext>) {
        let ExtPayload::SyscallActivity { histogram, .. } = &event.payload else {
            return;
        };
        // The share of syscall numbers the process used.
        let used = histogram.iter().filter(|count| **count > 0).count();
        let score = used as f32 / histogram.len() as f32;
        if score < THRESHOLD {
            return;
        }
        let mut description = format!("{used} different syscalls");
        // The model's context: the last events of the process.
        let window = event
            .header
            .subject
            .as_ref()
            .and_then(|subject| cx.table().window(subject.id()));
        if let Some((events, spans_gap)) = window {
            let kinds: Vec<_> = events
                .iter()
                .map(|event| event.payload.kind().name())
                .collect();
            description += &format!(", after {}", kinds.join(", "));
            if spans_gap {
                description += " (some lost)";
            }
        }
        cx.report(ExtThreatKind::Ml { score }, description);
    }
}
