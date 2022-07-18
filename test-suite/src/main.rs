#![allow(unused_imports)]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use bpf_common::test_runner::{TestCase, TestReport};
use libtest_mimic::{run_tests, Arguments, Outcome, Test};

// Import the modules,  this is needed to make inventory work
use file_system_monitor;
use tokio::sync::mpsc;

fn main() {
    // Parse command line arguments
    let mut args = Arguments::from_args();

    // Since we're pinning maps, we don't support concurrency.
    args.num_threads = Some(1);

    let (tx_log, rx_log) = mpsc::unbounded_channel();
    log::set_boxed_logger(Box::new(SimpleLogger(tx_log)))
        .map(|()| log::set_max_level(log::LevelFilter::Info))
        .expect("initalizing logger failed");

    let modules = [(
        "file-system-monitor",
        file_system_monitor::test_suite::tests,
    )];

    let tests = modules
        .into_iter()
        .flat_map(move |(module, tests)| {
            tests()
                .into_iter()
                .map(move |TestCase { name, test }| Test {
                    name: format!("{module}::{name}"),
                    kind: String::new(),
                    is_ignored: false,
                    is_bench: false,
                    // libtest_mimic requires data to be Sync,
                    // so we wrap it
                    data: Arc::new(Mutex::new(Some(test))),
                })
        })
        .collect();

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime init failed");
    #[cfg(debug_assertions)]
    let _stop_handle = rt.spawn(bpf_common::trace_pipe::start());
    let rx_log = Arc::new(Mutex::new(rx_log));
    run_tests(&args, tests, move |test| {
        rt.block_on(async {
            let test = (test.data.lock().unwrap().take()).unwrap();
            let TestReport { success, mut lines } = {
                bpf_common::trace_pipe::start().await;
                tokio::time::sleep(Duration::from_secs(1)).await;
                test.await
            };

            lines.push(String::new());
            while let Ok(log) = rx_log.lock().unwrap().try_recv() {
                lines.push(log);
            }

            //let success = false;
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
