//! Prints the records of the process probe, to review the ring and the record
//! ABI. Needs root.
//!
//!     cargo build -p next-bpf --example dump
//!     sudo target/debug/examples/dump [ring size in KiB]
//!
//! A small ring (e.g. 16) loses records under load; every loss is printed at
//! its position. On Ctrl-C it checks that every process started while the
//! probe was attached had its fork before its exec and exit.

use std::collections::HashSet;

use next_bpf::{
    abi::pulsar_subject,
    loader::{Loader, LoaderConfig},
    process::{self, ProcessRecord},
    record::{Field, RecordView},
    ring::{LossCounters, LossCursor, Record, Ring},
};
use nix::time::{ClockId, clock_gettime};
use tokio::sync::mpsc;

const CHANNEL_SIZE: usize = 4096;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut config = LoaderConfig::default();
    if let Some(kib) = std::env::args().nth(1) {
        config.ring_size = kib.parse::<u32>()? * 1024;
    }
    let mut loader = Loader::new(config)?;
    let mut probe = loader.load(&process::SPEC)?;
    let producer = probe.producer();
    let ring = Ring::open(loader.pin_dir())?;
    let losses = LossCounters::open(loader.pin_dir())?;

    // Reading starts before the programs are attached.
    let (tx, mut rx) = mpsc::channel::<Record>(CHANNEL_SIZE);
    let ingest = tokio::spawn(ring.run(tx));
    loader.attach(&mut probe)?;
    let attached_at = boot_time_ns()?;
    eprintln!("process probe attached as producer {producer}");

    let mut cursor = LossCursor::default();
    let mut check = OrderCheck::new(attached_at);
    let mut invalid = 0u64;
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    loop {
        let record = tokio::select! {
            _ = &mut ctrl_c => break,
            record = rx.recv() => match record {
                Some(record) => record,
                None => break,
            },
        };
        let view = match record.view() {
            Ok(view) => view,
            Err(err) => {
                invalid += 1;
                println!("invalid record: {err}");
                continue;
            }
        };
        let lost = cursor.advance(view.header());
        if lost > 0 {
            check.losses += u64::from(lost);
            println!("--- {lost} records lost here");
        }
        if view.producer() != producer {
            invalid += 1;
            println!("record of unknown producer {}", view.producer());
            continue;
        }
        match process::decode(&view) {
            Ok(decoded) => {
                println!("{}", line(&view, &decoded));
                if let Some(subject) = view.subject() {
                    check.observe(subject, &decoded);
                }
            }
            Err(err) => {
                invalid += 1;
                println!("invalid record: {err}");
            }
        }
    }

    drop(probe);
    ingest.abort();
    let counted = losses.total()?;
    let _ = loader.remove_pins();
    eprintln!();
    eprintln!("records: {}, invalid: {invalid}", check.records);
    eprintln!(
        "lost: {} seen in headers, {counted} counted by the probes",
        check.losses
    );
    eprintln!(
        "processes started after attach: {}, exec or exit before fork: {}",
        check.started, check.inversions
    );
    Ok(())
}

fn line(view: &RecordView, record: &ProcessRecord) -> String {
    let header = view.header();
    let subject = match view.subject() {
        Some(s) => format!(
            "tgid={} ppid={} uid={} exec_id={} cgroup={}",
            s.tgid, s.ppid, s.uid, s.exec_id, s.cgroup_id
        ),
        None => "unattributed".to_string(),
    };
    let body = match record {
        ProcessRecord::Fork { container, .. } => format!("fork container={container:?}"),
        ProcessRecord::Exec {
            argc,
            filename,
            argv,
            container,
            ..
        } => format!(
            "exec {} argc={argc} argv=[{}] container={container:?}",
            field(filename),
            argv.map(|argv| argv.split_nul().collect::<Vec<_>>().join(", "))
                .unwrap_or_else(|| "?".to_string())
        ),
        ProcessRecord::Exit { exit_code } => format!("exit code={exit_code}"),
        ProcessRecord::ChangeParent { ppid } => format!("change_parent ppid={ppid}"),
        ProcessRecord::CredsChange { uid, gid } => format!("creds_change uid={uid} gid={gid}"),
    };
    format!(
        "{:>15} lost={:<5} {subject} {body}",
        header.timestamp, header.lost
    )
}

fn field(field: &Option<Field>) -> String {
    match field {
        None => "?".to_string(),
        Some(field) if field.truncated => format!("{}...", field.to_string_lossy()),
        Some(field) => field.to_string_lossy().into_owned(),
    }
}

fn boot_time_ns() -> nix::Result<u64> {
    let now = clock_gettime(ClockId::CLOCK_BOOTTIME)?;
    Ok(now.tv_sec() as u64 * 1_000_000_000 + now.tv_nsec() as u64)
}

/// Counts processes started after attach whose exec or exit came before
/// their fork. With no losses there must be none.
struct OrderCheck {
    attached_at: u64,
    forked: HashSet<(u32, u64)>,
    records: u64,
    losses: u64,
    started: u64,
    inversions: u64,
}

impl OrderCheck {
    fn new(attached_at: u64) -> Self {
        Self {
            attached_at,
            forked: HashSet::new(),
            records: 0,
            losses: 0,
            started: 0,
            inversions: 0,
        }
    }

    fn observe(&mut self, subject: &pulsar_subject, record: &ProcessRecord) {
        self.records += 1;
        let process = (subject.tgid, subject.start_time);
        match record {
            ProcessRecord::Fork { .. } => {
                if subject.start_time > self.attached_at {
                    self.started += 1;
                }
                self.forked.insert(process);
            }
            ProcessRecord::Exec { .. } | ProcessRecord::Exit { .. } => {
                if subject.start_time > self.attached_at && !self.forked.contains(&process) {
                    self.inversions += 1;
                    println!("!!! {process:?} without an earlier fork");
                }
                if matches!(record, ProcessRecord::Exit { .. }) {
                    self.forked.remove(&process);
                }
            }
            _ => {}
        }
    }
}
