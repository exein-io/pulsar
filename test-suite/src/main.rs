#![allow(unused_imports)]

use bpf_common::test_runner::IntegrationTest;
use libtest_mimic::{run_tests, Arguments, Outcome, Test};

// Import the modules,  this is needed to make inventory work
use file_system_monitor;

fn main() {
    // Parse command line arguments
    let args = Arguments::from_args();

    let modules = [(
        "file-system-monitor",
        file_system_monitor::test_suite::tests,
    )];

    let tests = modules
        .into_iter()
        .flat_map(move |(module, tests)| {
            tests().into_iter().map(move |(test_name, test_fn)| Test {
                name: format!("{module}::{test_name}"),
                kind: String::new(),
                is_ignored: false,
                is_bench: false,
                data: test_fn,
            })
        })
        .collect();

    let rt = tokio::runtime::Runtime::new().unwrap();
    run_tests(&args, tests, move |test| {
        rt.block_on(async move {
            (test.data)().await;
            Outcome::Passed
        })
    })
    .exit();
}
