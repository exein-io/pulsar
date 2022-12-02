mod test_suite_runner;

pub use test_suite_runner::TestSuiteRunner;

/// Returns the testable modules of Pulsar
pub fn modules() -> Vec<bpf_common::test_runner::TestSuite> {
    vec![
        bpf_common::feature_autodetect::test_suite::tests(),
        file_system_monitor::test_suite::tests(),
        //network_monitor::test_suite::tests(),
        //process_monitor::test_suite::tests(),
    ]
}
