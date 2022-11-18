use test_suite::{modules, TestSuiteRunner};

#[tokio::main]
async fn main() {
    TestSuiteRunner::spawn().run_tests(modules()).await;
}
