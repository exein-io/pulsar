//! Test utility for eBPF programs
//!
//! Example usage:
//! ```
//! #[tokio::test]
//! async fn test_file_creation() {
//!     let fname = "file_name_1";
//!     let path = "/tmp/file_name_1";
//!     let result = TestRunner::with_ebpf(program)
//!         .run(|| {
//!             let _ = std::fs::remove_file(path);
//!             std::fs::File::create(path).expect("creating file failed");
//!         })
//!         .await;
//!     result.expect(|e: &EventT| {
//!         e.pid == std::process::id()
//!             && bpf_common::get_string(&e.filename) == fname
//!             && result.was_running_at(e.timestamp)
//!     });
//! }
//! ```

use std::{fmt::Display, future::Future, pin::Pin, time::Duration};

use anyhow::Context;
use tokio::sync::mpsc;

use crate::{
    program::{BpfContext, BpfEvent, BpfLogLevel, Pinning},
    time::Timestamp,
    BpfSender, Pid, Program, ProgramError,
};

const MAX_TIMEOUT: Duration = Duration::from_millis(30);

pub struct TestCase {
    pub name: &'static str,
    pub test: Pin<Box<dyn Future<Output = TestReport> + Send>>,
}

impl TestCase {
    pub fn new(
        name: &'static str,
        test: impl Future<Output = TestReport> + 'static + Send,
    ) -> Self {
        Self {
            name,
            test: Box::pin(test),
        }
    }
}

pub struct TestRunner<'a, T: Display> {
    ebpf: Pin<Box<dyn Future<Output = Result<Program, ProgramError>> + Send>>,
    trigger_program: Box<dyn FnOnce() + 'a + Send>,
    expectations: Vec<Expectation<T>>,
    rx: mpsc::UnboundedReceiver<BpfEvent<T>>,
}

enum Expectation<T> {
    Predicate(Box<dyn Fn(&BpfEvent<T>) -> bool + Send>),
    Checks {
        pid: Option<Pid>,
        time_bound: bool,
        checks: Vec<Check<T>>,
    },
}

impl<'a, T: Display> TestRunner<'a, T> {
    pub fn with_ebpf<P, Fut>(ebpf_fn: P) -> Self
    where
        P: Fn(BpfContext, TestSender<T>) -> Fut,
        Fut: Future<Output = Result<Program, ProgramError>> + 'static + Send,
    {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .is_test(true)
            .format_timestamp(None)
            .target(env_logger::Target::Stdout)
            .try_init();
        let (tx, rx) = mpsc::unbounded_channel();
        let sender = TestSender { tx };
        let ctx = BpfContext::new(Pinning::Disabled, 512, BpfLogLevel::Debug).unwrap();
        // Wait ebpf startup
        Self {
            rx,
            ebpf: Box::pin(ebpf_fn(ctx, sender)),
            trigger_program: Box::new(|| {}),
            expectations: Vec::new(),
        }
    }

    pub fn run(mut self, trigger_program: impl FnOnce() + 'a + Send) -> Self {
        self.trigger_program = Box::new(trigger_program);
        self
    }

    /// Assert the provided predicate matches at least one event
    pub fn expect(
        &mut self,
        predicate: impl Fn(&BpfEvent<T>) -> bool + 'static + Send,
    ) -> &mut Self {
        self.expectations
            .push(Expectation::Predicate(Box::new(predicate)));
        self
    }

    /// Make sure the eBPF program produced at least one event maching all checks.
    pub fn expect_custom_event(&mut self, checks: Vec<Check<T>>) -> &mut Self {
        self.expectations.push(Expectation::Checks {
            pid: None,
            time_bound: false,
            checks,
        });
        self
    }

    /// Make sure there's an event:
    /// - matching all expectations
    /// - produced during the collection interval
    /// - coming by the current process.
    pub fn expect_event(mut self, checks: Vec<Check<T>>) -> Self {
        self.expectations.push(Expectation::Checks {
            pid: Some(Pid::from_raw(std::process::id() as i32)),
            time_bound: true,
            checks,
        });
        self
    }

    /// Make sure there's an event:
    /// - matching all expectations
    /// - produced during the collection interval
    /// - coming by the specified process.
    pub fn expect_event_from_pid(&mut self, pid: Pid, checks: Vec<Check<T>>) -> &mut Self {
        self.expectations.push(Expectation::Checks {
            pid: Some(pid),
            time_bound: true,
            checks,
        });
        self
    }

    pub async fn report(mut self) -> TestReport {
        let _program = self.ebpf.await.context("running eBPF").unwrap();
        // Run the triggering code
        let start_time = Timestamp::now();
        (self.trigger_program)();
        let end_time = Timestamp::now();
        // Wait ebpf to process pending events
        tokio::time::sleep(MAX_TIMEOUT).await;
        // Collect events
        let events: Vec<_> = std::iter::from_fn(|| self.rx.try_recv().ok()).collect();

        let mut success = true;
        let mut lines = Vec::new();
        // print all events
        events.iter().for_each(|e| lines.push(e.to_string()));

        for expectation in self.expectations {
            match expectation {
                Expectation::Predicate(predicate) => {
                    let found = events.iter().map(predicate).any(|x| x);
                    if !found {
                        lines.push(format!("event not found among {} analyzed", events.len()));
                        success = false;
                    }
                }
                Expectation::Checks {
                    pid,
                    time_bound,
                    mut checks,
                } => {
                    if let Some(pid) = pid {
                        checks.push(pid_check(pid));
                    }
                    if time_bound {
                        checks.push(timestamp_check(start_time, end_time));
                    }
                    success = success && run_checks(&events, checks, &mut lines);
                }
            }
        }
        TestReport { success, lines }
    }
}

#[must_use]
pub struct TestReport {
    pub success: bool,
    pub lines: Vec<String>,
}

/// Make sure the eBPF program produced at least one event maching all checks.
pub fn run_checks<T: std::fmt::Display>(
    events: &Vec<BpfEvent<T>>,
    checks: Vec<Check<T>>,
    lines: &mut Vec<String>,
) -> bool {
    // for each event, run all checks
    let results: Vec<(&BpfEvent<T>, usize, Vec<CheckResult>)> = events
        .iter()
        .map(|event| {
            let results: Vec<CheckResult> = checks.iter().map(|c| (c.check_fn)(event)).collect();
            let score = results.iter().filter(|x| x.success).count();
            (event, score, results)
        })
        .collect();

    // check how many checks have passed
    let max_score = match results.iter().map(|x| x.1).max() {
        Some(max_score) => max_score,
        None => {
            lines.push("No events generated".to_string());
            return false;
        }
    };

    // if no event satisfies all cheks, we print a report table for each event
    if max_score != checks.len() {
        let best_results = results.into_iter().filter(|x| x.1 == max_score);
        lines.push("No event found matching results:".to_string());
        for (event, score, check_results) in best_results {
            lines.push(format!("{} ({}/{})", event, score, checks.len()));
            for (check_result, check) in check_results.iter().zip(checks.iter()) {
                if check_result.success {
                    lines.push(format!(
                        "- {}: {} (OK)",
                        check.description, check_result.expected
                    ));
                } else {
                    lines.push(format!("- {}: (FAIL)", check.description));
                    lines.push(format!("  |    found: {}", check_result.found));
                    lines.push(format!("  | expected: {}", check_result.expected));
                }
            }
            lines.push(String::new());
        }
        false
    } else {
        true
    }
}

pub type CheckFunction<T> = Box<dyn Fn(&BpfEvent<T>) -> CheckResult>;

/// A Check is an expectation about a BpfEvent which should be emitted.
/// This allows to split test expectations in different lines, making it easier to spot the error.
/// Build this is using the `event_check!` macro.
pub struct Check<T> {
    pub description: &'static str,
    pub check_fn: Box<dyn Fn(&BpfEvent<T>) -> CheckResult + Send>,
}

impl<T> Check<T> {
    pub fn new(
        description: &'static str,
        check_fn: impl Fn(&BpfEvent<T>) -> CheckResult + 'static + Send,
    ) -> Self {
        Self {
            description,
            check_fn: Box::new(check_fn),
        }
    }
}

/// Make sure the pid of an event matches the provided one
pub fn pid_check<T>(pid: Pid) -> Check<T> {
    Check::new("pid", move |event: &BpfEvent<_>| CheckResult {
        success: event.pid == pid,
        found: format!("{}", event.pid),
        expected: format!("{}", pid),
    })
}

/// Make sure the timestamp of an event matches the data collection period
pub fn timestamp_check<T>(start_time: Timestamp, end_time: Timestamp) -> Check<T> {
    Check::new("timestamp", move |event: &BpfEvent<_>| CheckResult {
        success: start_time <= event.timestamp && event.timestamp <= end_time,
        found: format!("{}", event.timestamp),
        expected: format!("{} - {}", start_time, end_time),
    })
}

pub struct CheckResult {
    /// Weather or not the event passed this test
    pub success: bool,
    /// String representation of the actual value produced
    pub found: String,
    /// String representation of the value which should have been produced
    pub expected: String,
}

/// event_check! makes it easy to build a list of checks for a given enum variant.
/// Example usage from network monitor:
///
/// (...).expect_event(event_check!(
///    NetworkEvent::Close,
///    (sport, source.port(), "source port"),
///    (dport, dest.port().to_be(), "dest port (be)"),
///    (ip_ver, ipver(dest), "ip version"),
///    (saddr, addr_to_array(source), "source address"),
///    (daddr, addr_to_array(dest), "dest address")
/// ));
#[macro_export]
macro_rules! event_check {
    ($event:tt :: $subtype:tt, $(($left:ident, $right:expr, $description:literal)),*) => {
        {
            use bpf_common::program::BpfEvent;
            use bpf_common::test_runner::{Check, CheckResult};
            let mut checks = Vec::new();
            checks.push(Check::new("event type", move |event: &BpfEvent<_>| {
                CheckResult {
                    success: matches!(event.payload, $event::$subtype {..}),
                    found: String::new(),
                    expected: stringify!($event::$subtype).to_string(),
                }
            }));
            $(
                let expected_value = $right;
                checks.push(Check::new(
                    $description,
                    move |event: &BpfEvent<_>| match event.payload {
                        $event::$subtype { ref $left, .. } => CheckResult {
                            success: $left == &expected_value,
                            found: format!("{:?}", $left),
                            expected: format!("{:?}", expected_value),
                        },
                        _ => CheckResult {
                            success: false,
                            found: format!("wrong variant"),
                            expected: format!("{:?}", expected_value),
                        },
                    },
                ));
            )*
            checks
        }
    }
}

/// Simple BpfSender used to collect `bpf_common::program::Program` events.
pub struct TestSender<T> {
    tx: mpsc::UnboundedSender<BpfEvent<T>>,
}

impl<T> Clone for TestSender<T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

impl<T: Send + 'static> BpfSender<T> for TestSender<T> {
    fn send(&mut self, data: Result<BpfEvent<T>, ProgramError>) {
        let data = data.map_err(anyhow::Error::from).unwrap();
        assert!(self.tx.send(data).is_ok());
    }
}
