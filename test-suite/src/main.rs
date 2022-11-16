use test_suite::TestSuiteRunner;

#[tokio::main]
async fn main() {
    TestSuiteRunner::spawn()
        .run_tests(vec![
            bpf_common::feature_autodetect::test_suite::tests(),
            file_system_monitor::test_suite::tests(),
            network_monitor::test_suite::tests(),
            process_monitor::test_suite::tests(),
            syscall_monitor::test_suite::tests(),
        ])
        .await;
}
