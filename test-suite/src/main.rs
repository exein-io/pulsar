use nix::unistd::geteuid;
use test_suite::{modules, TestSuiteRunner};

#[tokio::main]
async fn main() {
    if geteuid().is_root() {
        TestSuiteRunner::spawn().run_tests(modules()).await;
    } else {
        eprintln!("test-suite must be run as root");
        std::process::exit(1);
    }
}
