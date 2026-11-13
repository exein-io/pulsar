//! The processor: the one consumer of the ring. It decodes records, keeps the
//! process table, runs detectors and completes their threats.
//!
//! The core, [`Processor::process`], is synchronous and never blocks.
//! [`Processor::run`] drives it from a tokio channel; embedders and tests can
//! call `process` themselves.

use std::{collections::HashMap, future::Future, sync::Arc, time::SystemTime};

use next_bpf::{
    ProducerId,
    ring::{LossCursor, Record},
};
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

use crate::{
    Schema,
    event::{Event, Header, ProcessId, Subject},
    payload::{KindOf, PayloadKind, PayloadSet},
    probe::{Decoded, Probe},
    seed::SeedProcess,
    table::{ProcessTable, TableConfig},
    threat::Threat,
    time::boot_to_system,
};

/// What the processor consumes, in stream order.
pub enum Input {
    Record(Record),
    /// Processes read from /proc at start, placed where the reading finished.
    Seed(Vec<SeedProcess>),
}

impl From<Record> for Input {
    fn from(record: Record) -> Self {
        Input::Record(record)
    }
}

/// The payload kinds a detector wants to see.
pub enum Interest<K> {
    All,
    Kinds(Vec<K>),
}

impl<K: PayloadKind> Interest<K> {
    /// Indexed by [`PayloadKind::index`].
    fn mask(&self) -> Vec<bool> {
        match self {
            Interest::All => vec![true; K::ALL.len()],
            Interest::Kinds(kinds) => {
                let mut mask = vec![false; K::ALL.len()];
                for kind in kinds {
                    mask[kind.index()] = true;
                }
                mask
            }
        }
    }
}

pub trait Detector<S: Schema>: Send + 'static {
    fn name(&self) -> &'static str;

    fn interest(&self) -> Interest<KindOf<S>>;

    /// Must not block: it runs on the processor, between two records.
    fn on_event(&mut self, event: &Arc<Event<S::Payload>>, cx: &mut DetectCtx<'_, S>);
}

/// What a detector can read, and how it reports.
pub struct DetectCtx<'a, S: Schema> {
    table: &'a ProcessTable<S::Payload>,
    event: &'a Arc<Event<S::Payload>>,
    detector: &'static str,
    found: &'a mut Vec<Found<S>>,
}

impl<S: Schema> DetectCtx<'_, S> {
    pub fn table(&self) -> &ProcessTable<S::Payload> {
        self.table
    }

    /// Reports a threat triggered by the current event.
    pub fn report(&mut self, kind: impl Into<S::ThreatKind>, description: impl Into<String>) {
        self.found.push(Found {
            detector: self.detector,
            kind: kind.into(),
            description: description.into(),
            event: Some(self.event.clone()),
            process: self.event.header.subject.as_ref().map(Subject::id),
        });
    }

    /// Reports a threat about a process, not tied to one event.
    pub fn report_process(
        &mut self,
        process: ProcessId,
        kind: impl Into<S::ThreatKind>,
        description: impl Into<String>,
    ) {
        self.found.push(Found {
            detector: self.detector,
            kind: kind.into(),
            description: description.into(),
            event: None,
            process: Some(process),
        });
    }
}

/// A threat before the processor added the subject and lineage.
struct Found<S: Schema> {
    detector: &'static str,
    kind: S::ThreatKind,
    description: String,
    event: Option<Arc<Event<S::Payload>>>,
    process: Option<ProcessId>,
}

pub type ReportError = Box<dyn std::error::Error + Send + Sync>;

/// Receives threats on its own task, from a queue that drops the oldest
/// threat when the reporter falls behind.
pub trait Reporter<S: Schema>: Send + 'static {
    fn name(&self) -> &'static str;

    fn report(
        &mut self,
        threat: Arc<Threat<S>>,
    ) -> impl Future<Output = Result<(), ReportError>> + Send;
}

/// Everything the processor produced, for the tap. Lossy.
pub enum Tapped<S: Schema> {
    Event(Arc<Event<S::Payload>>),
    Threat(Arc<Threat<S>>),
}

impl<S: Schema> Clone for Tapped<S> {
    fn clone(&self) -> Self {
        match self {
            Tapped::Event(event) => Tapped::Event(event.clone()),
            Tapped::Threat(threat) => Tapped::Threat(threat.clone()),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub records: u64,
    /// Records that failed validation or decoding.
    pub invalid: u64,
    pub unknown_producer: u64,
    /// Records lost in the kernel, seen as jumps of the header's counter.
    pub lost: u64,
    pub threats: u64,
}

pub struct Processor<S: Schema> {
    probes: HashMap<ProducerId, Box<dyn Probe<S>>>,
    /// Each with its [`Interest::mask`].
    detectors: Vec<(Vec<bool>, Box<dyn Detector<S>>)>,
    table: ProcessTable<S::Payload>,
    cursor: LossCursor,
    tap: broadcast::Sender<Tapped<S>>,
    decoded: Decoded<S::Payload>,
    found: Vec<Found<S>>,
    stats: Stats,
}

impl<S: Schema> Processor<S> {
    pub fn new(table: TableConfig, tap: broadcast::Sender<Tapped<S>>) -> Self {
        Self {
            probes: HashMap::new(),
            detectors: Vec::new(),
            table: ProcessTable::new(table),
            cursor: LossCursor::default(),
            tap,
            decoded: Decoded::default(),
            found: Vec::new(),
            stats: Stats::default(),
        }
    }

    /// Records from `producer` are decoded by `probe`.
    pub fn add_probe(&mut self, producer: ProducerId, probe: Box<dyn Probe<S>>) {
        self.probes.insert(producer, probe);
    }

    pub fn add_detector(&mut self, detector: Box<dyn Detector<S>>) {
        self.detectors.push((detector.interest().mask(), detector));
    }

    pub fn table(&self) -> &ProcessTable<S::Payload> {
        &self.table
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Processes one input and appends the threats it caused to `threats`.
    pub fn process(&mut self, input: Input, threats: &mut Vec<Arc<Threat<S>>>) {
        match input {
            Input::Record(record) => self.record(&record, threats),
            Input::Seed(processes) => self.table.seed(processes),
        }
    }

    /// Processes inputs until `inputs` closes, sending threats to `threats`.
    pub async fn run(
        mut self,
        mut inputs: mpsc::Receiver<Input>,
        threats: broadcast::Sender<Arc<Threat<S>>>,
    ) -> Stats {
        let mut found = Vec::new();
        while let Some(input) = inputs.recv().await {
            self.process(input, &mut found);
            for threat in found.drain(..) {
                // No receiver means no reporter: nothing to do.
                let _ = threats.send(threat);
            }
        }
        self.stats
    }

    fn record(&mut self, record: &Record, threats: &mut Vec<Arc<Threat<S>>>) {
        self.stats.records += 1;
        let view = match record.view() {
            Ok(view) => view,
            Err(err) => {
                self.stats.invalid += 1;
                log::debug!("invalid record: {err}");
                return;
            }
        };
        let lost = self.cursor.advance(view.header());
        if lost > 0 {
            self.stats.lost += u64::from(lost);
            self.table.note_loss(lost);
        }
        let Some(probe) = self.probes.get(&view.producer()) else {
            self.stats.unknown_producer += 1;
            return;
        };
        self.decoded.clear();
        if let Err(err) = probe.decode(&view, &mut self.decoded) {
            self.stats.invalid += 1;
            log::debug!("{}: {err}", probe.spec().name);
            return;
        }

        let raw = view.header();
        let mut header = Header {
            timestamp: boot_to_system(raw.timestamp),
            source: probe.spec().name,
            subject: view.subject().map(Subject::from),
            image: None,
            container: None,
            fork_time: None,
        };
        if let (Some(lifecycle), Some(subject)) = (&self.decoded.lifecycle, &header.subject) {
            self.table.apply(subject, raw.timestamp, lifecycle);
        }
        self.table.enrich(&mut header);

        for payload in self.decoded.payloads.drain(..) {
            let event = Arc::new(Event {
                header: header.clone(),
                payload,
            });
            self.table.remember(&event);
            let kind = event.payload.kind().index();
            for (interest, detector) in &mut self.detectors {
                if !interest[kind] {
                    continue;
                }
                let mut cx = DetectCtx {
                    table: &self.table,
                    event: &event,
                    detector: detector.name(),
                    found: &mut self.found,
                };
                detector.on_event(&event, &mut cx);
            }
            let _ = self.tap.send(Tapped::Event(event));
        }

        for found in self.found.drain(..) {
            let threat = Arc::new(Threat {
                id: Uuid::now_v7(),
                detector: found.detector,
                kind: found.kind,
                description: found.description,
                event: found.event,
                subject: found
                    .process
                    .map(|id| self.table.snapshot(id))
                    .unwrap_or_default(),
                lineage: found
                    .process
                    .map(|id| self.table.lineage(id))
                    .unwrap_or_default(),
                timestamp: SystemTime::now(),
            });
            self.stats.threats += 1;
            let _ = self.tap.send(Tapped::Threat(threat.clone()));
            threats.push(threat);
        }
    }
}
