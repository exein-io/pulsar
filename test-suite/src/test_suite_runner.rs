use std::panic::AssertUnwindSafe;

use bpf_common::test_runner::{TestCase, TestReport, TestSuite};
use futures::FutureExt;
use libtest_mimic::{Arguments, Failed, Trial};
use tokio::sync::{mpsc, oneshot};

pub struct TestSuiteRunner {
    tx_test: mpsc::Sender<TestRequest>,
}

struct TestRequest {
    test_case: TestCase,
    tx_reply: oneshot::Sender<Result<(), Failed>>,
}

impl TestSuiteRunner {
    /// Spawn the actual test runner in a background task. This is needed to run
    /// async tests from libtest_mimic.
    pub fn spawn() -> Self {
        // Since writing to stdout will mess the output,
        // we'll write logs to a channel instead.
        let (tx_log, mut rx_log) = mpsc::unbounded_channel();
        replace_logger(tx_log.clone());
        replace_panic_hook(tx_log);
        bpf_common::bump_memlock_rlimit().unwrap();
        // Spawn the actual runner, which receives tests over a channel.
        let (tx_test, mut rx_test) = mpsc::channel::<TestRequest>(1);
        tokio::spawn(async move {
            // Start the trace_pipe eBPF program log interceptor
            #[cfg(debug_assertions)]
            let _stop_handle = tokio::spawn(bpf_common::trace_pipe::start());

            while let Some(test_request) = rx_test.recv().await {
                // Run actual test and treat eventual panics as errors.
                let TestReport { success, mut lines } =
                    AssertUnwindSafe(test_request.test_case.test)
                        .catch_unwind()
                        .await
                        .unwrap_or(TestReport {
                            success: false,
                            lines: vec![],
                        });

                // Collect logs and append them to the report lines
                while let Ok(log) = rx_log.try_recv() {
                    lines.push(log);
                }

                // Display output through libtest mimic
                test_request
                    .tx_reply
                    .send(if success {
                        Ok(())
                    } else {
                        Err(lines.join("\n").into())
                    })
                    .unwrap();
            }
        });

        Self { tx_test }
    }

    /// Run our test-suite with libtest-mimic.
    pub async fn run_tests(&self, modules: Vec<TestSuite>) {
        let tests = modules
            .into_iter()
            // Fetch all the test cases for all module test suites
            .flat_map(|test_suite: TestSuite| {
                test_suite
                    .tests
                    .into_iter()
                    .map(|test_case| (test_suite.name.to_string(), test_case))
            })
            // Map to a libtest_mimic runner which forwards execution to the background thread
            .map(|(module_name, test_case)| {
                let test_name = format!("{}::{}", module_name, test_case.name);
                let (tx_reply, rx_reply) = oneshot::channel();
                let test_request = TestRequest {
                    tx_reply,
                    test_case,
                };
                let tx_test = self.tx_test.clone();
                let run_in_background = move || {
                    tx_test
                        .blocking_send(test_request)
                        .map_err(|_| "Test runner failed to accept request")?;
                    rx_reply
                        .blocking_recv()
                        .map_err(|_| "Test runner failed to send reply")?
                };
                Trial::test(test_name, run_in_background)
            })
            .collect();

        // Parse command line arguments and run tests in a blocking task.
        let args = Arguments::from_args();
        tokio::task::spawn_blocking(move || {
            libtest_mimic::run(&args, tests).exit();
        })
        .await
        .unwrap();
    }
}

/// We want to show logs only for failed tests, so we use a simple
/// interceptor which sends them over a channel.
fn replace_logger(tx_log: mpsc::UnboundedSender<String>) {
    /// A simple logger which forwards logs over a chennel
    struct SimpleLogger(mpsc::UnboundedSender<String>);

    impl log::Log for SimpleLogger {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }
        fn log(&self, record: &log::Record) {
            self.0
                .send(format!(
                    "{}:{} -- {}",
                    record.level(),
                    record.target(),
                    record.args()
                ))
                .expect("forwarding logs failed");
        }
        fn flush(&self) {}
    }

    log::set_boxed_logger(Box::new(SimpleLogger(tx_log)))
        .map(|()| log::set_max_level(log::LevelFilter::Info))
        .expect("initalizing logger failed");
}

/// Replace the panic hook with one which sends a message over the log channel
fn replace_panic_hook(tx_log: mpsc::UnboundedSender<String>) {
    if std::env::var("USE_NORMAL_PANIC_HANDLER").is_err() {
        std::panic::set_hook(Box::new(move |panic_info| {
            let panic_msg = if let Some(msg) = panic_info.payload().downcast_ref::<&str>() {
                msg.to_string()
            } else if let Some(msg) = panic_info.payload().downcast_ref::<String>() {
                msg.to_string()
            } else {
                "Unknown panic error\nRe-run exporting the USE_NORMAL_PANIC_HANDLER env variable"
                    .to_string()
            };
            let location = panic_info
                .location()
                .map(ToString::to_string)
                .unwrap_or_else(|| "unknown location".to_string());
            let _ = tx_log.send(format!("❌ Panic: {panic_msg}\n  | at {location}"));
        }));
    }
}
