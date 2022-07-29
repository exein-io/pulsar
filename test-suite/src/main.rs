#![allow(unused_imports)]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use bpf_common::test_runner::{TestCase, TestReport, TestSuite};
use libtest_mimic::{run_tests, Arguments, Outcome, Test};
use tokio::sync::mpsc;

fn main() {
    // Parse command line arguments
    let mut args = Arguments::from_args();

    // Since we're pinning maps, we don't support concurrency.
    args.num_threads = Some(1);

    // We want to show logs only for failed tests, so we use a simple
    // interceptor which sends them over a channel.
    let (tx_log, rx_log) = mpsc::unbounded_channel();
    log::set_boxed_logger(Box::new(SimpleLogger(tx_log)))
        .map(|()| log::set_max_level(log::LevelFilter::Info))
        .expect("initalizing logger failed");

    // List of modules we want to test
    let modules = [
        file_system_monitor::test_suite::tests(),
        network_monitor::test_suite::tests(),
        process_monitor::test_suite::tests(),
        syscall_monitor::test_suite::tests(),
    ];

    // Convert our test suite to libtest-minic compatible ones
    let tests = modules
        .into_iter()
        .flat_map(move |test_suite: TestSuite| {
            test_suite
                .tests
                .into_iter()
                .map(move |test_case: TestCase| Test {
                    name: format!("{}::{}", test_suite.name, test_case.name),
                    kind: String::new(),
                    is_ignored: false,
                    is_bench: false,
                    // libtest_mimic requires data to be Sync, so we wrap it
                    data: Arc::new(Mutex::new(Some(test_case.test))),
                })
        })
        .collect();

    // Start tokio runtime
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime init failed");

    // Start trace_pipe log interceptor
    #[cfg(debug_assertions)]
    let _stop_handle = rt.spawn(bpf_common::trace_pipe::start());

    let rx_log = Arc::new(Mutex::new(rx_log));
    run_tests(&args, tests, move |test| {
        rt.block_on(async {
            // Run actual test
            let test = (test.data.lock().unwrap().take()).unwrap();
            let TestReport { success, mut lines } = test.await;

            // Collect logs and append them to the report lines
            while let Ok(log) = rx_log.lock().unwrap().try_recv() {
                lines.push(log);
            }

            // Display output through libtest mimic
            if success {
                Outcome::Passed
            } else {
                Outcome::Failed {
                    msg: Some(lines.join("\n")),
                }
            }
        })
    })
    .exit();
}

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
