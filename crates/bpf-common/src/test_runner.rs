//! Test utility for eBPF programs
//!
//! Example usage taken from file-system-monitor:
//! ```ignore
//! #[cfg(feature = "test-suite")]
//! pub mod test_suite {
//!     use super::*;
//!     use bpf_common::{
//!         event_check,
//!         test_runner::{TestCase, TestRunner, TestSuite},
//!     };
//!
//!     pub fn tests() -> TestSuite {
//!         TestSuite {
//!             name: "file-system-monitor",
//!             tests: vec![open_file()],
//!         }
//!     }
//!
//!     fn open_file() -> TestCase {
//!         TestCase::new("file_name", async {
//!             let path = std::env::temp_dir().join("file_name_1");
//!             TestRunner::with_ebpf(program)
//!                 .run(|| { std::fs::File::create(&path); } )
//!                 .await
//!                 .expect_event(event_check!(
//!                     FsEvent::FileCreated,
//!                     (filename, path.to_str().unwrap().into(), "filename")
//!                 ))
//!                 .report()
//!         })
//!     }
//! }
//! ```

use std::fmt::Debug;
use std::{future::Future, pin::Pin, time::Duration};

use anyhow::Context;
use bytes::Bytes;
use lazy_static::lazy_static;
use tokio::sync::mpsc;

use crate::feature_autodetect::lsm::lsm_supported;
use crate::{
    program::{BpfContext, BpfEvent, BpfLogLevel, Pinning},
    time::Timestamp,
    BpfSender, Pid, Program, ProgramError,
};

const MAX_TIMEOUT: Duration = Duration::from_millis(30);

/// Every module should export its own test suite
pub struct TestSuite {
    /// Name of the module
    pub name: &'static str,
    /// List of tests to run
    pub tests: Vec<TestCase>,
}

/// Every feature have a test case
pub struct TestCase {
    /// Name of the test
    pub name: &'static str,
    /// A test is an async function which returns a TestReport
    pub test: Pin<Box<dyn Future<Output = TestReport> + Send>>,
}

/// TestReport is the TestCase output
#[must_use]
pub struct TestReport {
    /// Wheather or not the test passed
    pub success: bool,
    /// Output describing the failure
    pub lines: Vec<String>,
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

/// TestRunner starts a eBPF program and collects into a TestResult all events
/// produced by the given trigger program.
pub struct TestRunner<T: Debug> {
    ebpf: Pin<Box<dyn Future<Output = Result<Program, ProgramError>> + Send>>,
    rx: mpsc::UnboundedReceiver<BpfEvent<T>>,
}

impl<T: Debug> TestRunner<T> {
    /// Set the eBPF program
    pub fn with_ebpf<P, Fut>(ebpf_fn: P) -> Self
    where
        P: Fn(BpfContext, TestSender<T>) -> Fut,
        Fut: Future<Output = Result<Program, ProgramError>> + 'static + Send,
    {
        // We use a channel to collect events
        let (tx, rx) = mpsc::unbounded_channel();
        let sender = TestSender { tx };

        lazy_static! {
            static ref BPF_CONTEXT: BpfContext =
                BpfContext::new(Pinning::Disabled, 512, BpfLogLevel::Debug, lsm_supported())
                    .unwrap();
        }

        let ctx = BPF_CONTEXT.clone();
        Self {
            rx,
            ebpf: Box::pin(ebpf_fn(ctx, sender)),
        }
    }

    /// Run the given triggering code and collect all events into a TestResult.
    pub async fn run<F>(mut self, trigger_program: F) -> TestResult<T>
    where
        F: FnOnce(),
    {
        let _program = self.ebpf.await.context("running eBPF").unwrap();
        // Run the triggering code
        let start_time = Timestamp::now();
        trigger_program();
        let end_time = Timestamp::now();
        // Wait ebpf to process pending events
        tokio::time::sleep(MAX_TIMEOUT).await;
        // Collect events
        let events: Vec<_> = std::iter::from_fn(|| self.rx.try_recv().ok()).collect();
        TestResult {
            start_time,
            end_time,
            events,
            expectations: Vec::new(),
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

/// Events collected by the TestRunner
pub struct TestResult<T: Debug> {
    /// When collection started
    pub start_time: Timestamp,
    /// When collection ended
    pub end_time: Timestamp,
    /// Collected events
    pub events: Vec<BpfEvent<T>>,

    /// Expectations for this test. These are checked by the `report`
    /// function and used to produce a TestReport.
    expectations: Vec<Expectation<T>>,
}

/// Expectation for a given test
enum Expectation<T> {
    /// The given predicate must match at least one of the generated events
    Predicate(Predicate<T>),
    /// At least one event must match all provided constraints
    Checks {
        /// Check the event comes from the configured pid, if one is specified
        pid: Option<Pid>,
        /// Enable checking that the event timestamp fits between the TestResult start/end time
        time_bound: bool,
        /// List of checks on the event properties
        checks: Vec<Check<T>>,
    },
}

/// A `Predicate<T>` is a function which takes a `BpfEvent<T>` and returns if
/// an expectation is satisfied.
type Predicate<T> = Box<dyn Fn(&BpfEvent<T>) -> bool + Send>;

impl<T: Debug> TestResult<T> {
    /// Assert the provided predicate matches at least one event
    pub fn expect(mut self, predicate: impl Fn(&BpfEvent<T>) -> bool + 'static + Send) -> Self {
        self.expectations
            .push(Expectation::Predicate(Box::new(predicate)));
        self
    }

    /// Make sure the eBPF program produced at least one event matching all checks.
    pub fn expect_custom_event(
        mut self,
        pid: Option<Pid>,
        time_bound: bool,
        checks: Vec<Check<T>>,
    ) -> Self {
        self.expectations.push(Expectation::Checks {
            pid,
            time_bound,
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
    pub fn expect_event_from_pid(mut self, pid: Pid, checks: Vec<Check<T>>) -> Self {
        self.expectations.push(Expectation::Checks {
            pid: Some(pid),
            time_bound: true,
            checks,
        });
        self
    }

    /// Search among the produced events one which satisfies all expectations.
    pub fn report(self) -> TestReport {
        let events = self.events;
        let mut success = true;
        let mut lines = Vec::new();
        // print all events
        lines.push(format!("* {} events generated:", events.len()));
        events.iter().for_each(|e| lines.push(format!("| {e:?}")));
        lines.push(String::new());

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
                        checks.push(timestamp_check(self.start_time, self.end_time));
                    }
                    success = success && run_checks(&events, checks, &mut lines);
                }
            }
        }
        TestReport { success, lines }
    }
}

/// Make sure the eBPF program produced at least one event maching all checks.
pub fn run_checks<T: std::fmt::Debug>(
    events: &[BpfEvent<T>],
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
        for (event, score, check_results) in best_results {
            lines.push(format!(
                "* Only ({}/{}) matches for \"{:?}\"",
                score,
                checks.len(),
                event
            ));
            for (check_result, check) in check_results.iter().zip(checks.iter()) {
                if check_result.success {
                    lines.push(format!(
                        "✓ {}: {}",
                        check.description, check_result.expected
                    ));
                } else {
                    lines.push(format!("❌ {}: (FAIL)", check.description));
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

/// A Check is an expectation about a BpfEvent which should be emitted.
/// This allows to split test expectations in different lines, making it easier to spot the error.
/// Build this is using the `event_check!` macro.
pub struct Check<T> {
    pub description: &'static str,
    pub check_fn: CheckFunction<T>,
}

/// A `CheckFunction<T>` is a function which takes a `BpfEvent<T>` and returns the description
/// of the test-result
type CheckFunction<T> = Box<dyn Fn(&BpfEvent<T>) -> CheckResult>;

impl<T> Check<T> {
    pub fn new(
        description: &'static str,
        check_fn: impl Fn(&BpfEvent<T>) -> CheckResult + 'static,
    ) -> Self {
        Self {
            description,
            check_fn: Box::new(check_fn),
        }
    }
}

/// Make sure the pid of an event matches the provided one
fn pid_check<T>(pid: Pid) -> Check<T> {
    Check::new("pid", move |event: &BpfEvent<_>| CheckResult {
        success: event.pid == pid,
        found: format!("{}", event.pid),
        expected: format!("{pid}"),
    })
}

/// Make sure the timestamp of an event matches the data collection period
fn timestamp_check<T>(start_time: Timestamp, end_time: Timestamp) -> Check<T> {
    Check::new("timestamp", move |event: &BpfEvent<_>| CheckResult {
        success: start_time <= event.timestamp && event.timestamp <= end_time,
        found: format!("{}", event.timestamp),
        expected: format!("{start_time} - {end_time}"),
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
            use bpf_common::test_runner::{Check, CheckResult, ComparableField};
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
                            success: {
                                ComparableField::equals($left, &expected_value, &event.buffer)
                            },
                            found: ComparableField::repr($left, &event.buffer),
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

/// Trait for event field types which can be compared inside the event_check macro.
/// A given type X can be compared to a different type T if X: ComparableField<T>
/// All methods take a Bytes buffer, where the implementation could read data from.
/// This allows BufferIndex to compare to a Vec<u8> to the pointed at slice.
pub trait ComparableField<T> {
    /// Check if the field equals the provided one, t.
    fn equals(&self, t: &T, buffer: &Bytes) -> bool;
    /// Get a textual debug representation of the field.
    fn repr(&self, buffer: &Bytes) -> String;
}

/// Every type which implements Debug and PartialEq is comparable to itself.
impl<T: PartialEq + std::fmt::Debug> ComparableField<T> for T {
    fn equals(&self, t: &T, _buffer: &Bytes) -> bool {
        self == t
    }
    fn repr(&self, _buffer: &Bytes) -> String {
        format!("{self:?}")
    }
}
