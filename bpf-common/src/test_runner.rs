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

pub struct TestRunner<T: Display> {
    ebpf: Pin<Box<dyn Future<Output = Result<Program, ProgramError>>>>,
    rx: mpsc::UnboundedReceiver<BpfEvent<T>>,
}

impl<T: Display> TestRunner<T> {
    pub fn with_ebpf<P, Fut>(ebpf_fn: P) -> Self
    where
        P: Fn(BpfContext, TestSender<T>) -> Fut,
        Fut: Future<Output = Result<Program, ProgramError>> + 'static,
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
        }
    }

    pub async fn run<F>(mut self, trigger_program: F) -> TestResult<T>
    where
        F: FnOnce(),
    {
        #[cfg(debug_assertions)]
        let _stop_handle = crate::trace_pipe::start().await;
        let _program = self.ebpf.await.context("running eBPF").unwrap();
        // Run the triggering code
        let start_time = Timestamp::now();
        trigger_program();
        let end_time = Timestamp::now();
        // Wait ebpf to process pending events
        tokio::time::sleep(MAX_TIMEOUT).await;
        // Collect events
        let events: Vec<_> = std::iter::from_fn(|| self.rx.try_recv().ok()).collect();
        // Cargo will display stdout only on failed tests, so it's useful
        // to print all produced events.
        events.iter().for_each(|e| println!("{}", e));
        TestResult {
            start_time,
            end_time,
            events,
        }
    }
}

pub struct TestResult<T: Display> {
    start_time: Timestamp,
    end_time: Timestamp,
    events: Vec<BpfEvent<T>>,
}

impl<T: Display> TestResult<T> {
    /// Assert the provided predicate matches at least one event
    pub fn expect<F>(&self, predicate: F)
    where
        F: Fn(&BpfEvent<T>) -> bool,
    {
        let found = self.events.iter().map(predicate).any(|x| x);
        if !found {
            panic!("event not found among {} analyzed", self.events.len());
        }
    }

    pub fn iter(&self) -> std::slice::Iter<'_, BpfEvent<T>> {
        self.events.iter()
    }

    /// Make sure the eBPF program produced at least one event maching all checks.
    pub fn expect_custom_event(&self, checks: Vec<Check<T>>) -> &Self {
        assert!(!self.events.is_empty());

        // for each event, run all checks
        let results: Vec<(&BpfEvent<T>, usize, Vec<CheckResult>)> = self
            .events
            .iter()
            .map(|event| {
                let results: Vec<CheckResult> =
                    checks.iter().map(|c| (c.check_fn)(event)).collect();
                let score = results.iter().filter(|x| x.success).count();
                (event, score, results)
            })
            .collect();

        // check how many checks have passed
        let max_score = results.iter().map(|x| x.1).max().unwrap();

        // if no event satisfies all cheks, we print a report table for each event
        if max_score != checks.len() {
            let best_results = results.into_iter().filter(|x| x.1 == max_score);
            for (event, score, check_results) in best_results {
                println!("\n{} ({}/{})", event, score, checks.len());
                for (check_result, check) in check_results.iter().zip(checks.iter()) {
                    if check_result.success {
                        println!("- {}: {} (OK)", check.description, check_result.expected);
                    } else {
                        println!("- {}: (FAIL)", check.description);
                        println!("  |    found: {}", check_result.found);
                        println!("  | expected: {}", check_result.expected);
                    }
                }
            }
            println!();
            panic!("No event found matching results");
        }
        self
    }

    /// Make sure there's an event:
    /// - matching all expectations
    /// - produced during the collection interval
    /// - coming by the current process.
    pub fn expect_event(&self, mut checks: Vec<Check<T>>) -> &Self {
        checks.insert(0, self.timestamp_check());
        checks.insert(0, Self::pid_check(Pid::from_raw(std::process::id() as i32)));
        self.expect_custom_event(checks)
    }

    /// Make sure there's an event:
    /// - matching all expectations
    /// - produced during the collection interval
    /// - coming by the specified process.
    pub fn expect_event_from_pid(&self, pid: Pid, mut checks: Vec<Check<T>>) -> &Self {
        checks.insert(0, self.timestamp_check());
        checks.insert(0, Self::pid_check(pid));
        self.expect_custom_event(checks)
    }

    /// Make sure the timestamp of an event matches the data collection period
    pub fn timestamp_check(&self) -> Check<T> {
        let start_time = self.start_time;
        let end_time = self.end_time;
        Check::new("timestamp", move |event: &BpfEvent<_>| CheckResult {
            success: start_time <= event.timestamp && event.timestamp <= end_time,
            found: format!("{}", event.timestamp),
            expected: format!("{} - {}", start_time, end_time),
        })
    }

    /// Make sure the pid of an event matches the provided one
    pub fn pid_check(pid: Pid) -> Check<T> {
        Check::new("pid", move |event: &BpfEvent<_>| CheckResult {
            success: event.pid == pid,
            found: format!("{}", event.pid),
            expected: format!("{}", pid),
        })
    }
}

pub type CheckFunction<T> = Box<dyn Fn(&BpfEvent<T>) -> CheckResult>;

/// A Check is an expectation about a BpfEvent which should be emitted.
/// This allows to split test expectations in different lines, making it easier to spot the error.
/// Build this is using the `event_check!` macro.
pub struct Check<T> {
    pub description: &'static str,
    pub check_fn: CheckFunction<T>,
}

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
