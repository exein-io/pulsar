//! Matching events against the patterns a test expects.
//!
//! Every pattern must match an event, in order. Every other event is ignored,
//! since the rest of the system keeps running during a test. Each pattern
//! takes the earliest event that fits: if any assignment of events to
//! patterns exists, this one is, so there is nothing to backtrack.

use std::{collections::BTreeSet, fmt::Write, sync::Arc};

use next_core::{
    event::Event,
    payload::{PayloadKind, PayloadSet},
};

use crate::{
    Outcome, Verdict,
    daemon::{Recording, subject_pid},
};

/// An event a test expects, of a kind, about a process, with an event of
/// payload `P`. The types of [`pattern`](crate::pattern) are patterns.
pub trait Pattern<P> {
    /// The name of the payload variant.
    fn kind(&self) -> &'static str;

    fn pid(&self) -> u32;

    /// The fields the pattern sets, checked on `event`. `None` when `event` is
    /// of another kind, or about no process.
    fn fields(&self, event: &Event<P>) -> Option<Vec<Field>>;
}

pub struct Field {
    pub name: &'static str,
    /// `None` when the field matches.
    pub mismatch: Option<String>,
}

fn is_about<P: PayloadSet>(pattern: &dyn Pattern<P>, event: &Event<P>) -> bool {
    event.payload.kind().name() == pattern.kind() && subject_pid(event) == Some(pattern.pid())
}

fn matches<P: PayloadSet>(pattern: &dyn Pattern<P>, event: &Event<P>) -> bool {
    is_about(pattern, event)
        && pattern
            .fields(event)
            .is_some_and(|fields| fields.iter().all(|field| field.mismatch.is_none()))
}

fn describe<P>(pattern: &dyn Pattern<P>) -> String {
    format!("{} of {}", pattern.kind(), pattern.pid())
}

pub fn expect<P: PayloadSet>(recording: &Recording<P>, patterns: &[&dyn Pattern<P>]) -> Outcome {
    Outcome {
        verdict: verdict(&recording.events, patterns),
        lost: recording.stats.lost,
        invalid: recording.stats.invalid,
    }
}

fn verdict<P: PayloadSet>(events: &[Arc<Event<P>>], patterns: &[&dyn Pattern<P>]) -> Verdict {
    let mut next = 0;
    for (index, pattern) in patterns.iter().enumerate() {
        match events[next..]
            .iter()
            .position(|event| matches(*pattern, event))
        {
            Some(offset) => next += offset + 1,
            None => return Verdict::Failed(report(events, patterns, index, next)),
        }
    }
    Verdict::Passed
}

/// The patterns that matched, why the next one didn't, and the events about
/// the processes of the patterns.
fn report<P: PayloadSet>(
    events: &[Arc<Event<P>>],
    patterns: &[&dyn Pattern<P>],
    failed: usize,
    from: usize,
) -> String {
    let mut out = String::new();
    for pattern in &patterns[..failed] {
        writeln!(out, "✓ {}", describe(*pattern)).unwrap();
    }
    let pattern = patterns[failed];
    writeln!(out, "✗ {}", describe(pattern)).unwrap();
    let mut candidates = events[from..]
        .iter()
        .filter(|event| is_about(pattern, event));
    let mut found = false;
    for event in candidates.by_ref() {
        found = true;
        writeln!(out, "    {:?}", event.payload).unwrap();
        for field in pattern.fields(event).unwrap_or_default() {
            match field.mismatch {
                None => writeln!(out, "      ✓ {}", field.name),
                Some(mismatch) => writeln!(out, "      ✗ {}: {mismatch}", field.name),
            }
            .unwrap();
        }
    }
    if !found {
        writeln!(out, "    no such event after the patterns above").unwrap();
    }
    for pattern in &patterns[failed + 1..] {
        writeln!(out, "  {}", describe(*pattern)).unwrap();
    }

    let pids: BTreeSet<u32> = patterns.iter().map(|pattern| pattern.pid()).collect();
    writeln!(out, "Events about {pids:?}:").unwrap();
    for event in events {
        if subject_pid(event).is_some_and(|pid| pids.contains(&pid)) {
            writeln!(out, "  {}: {:?}", event.header, event.payload).unwrap();
        }
    }
    out
}
