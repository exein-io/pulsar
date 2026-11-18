//! The harness of `test-suite-next`: a daemon per test, helper processes,
//! patterns of expected events, and outcomes on top of libtest-mimic.

pub mod daemon;
pub mod expect;
pub mod helper;
pub mod matcher;
mod outcome;
pub mod pattern;
mod vm;

use std::process::ExitCode;

pub use outcome::{Outcome, Test, TestResult, Verdict};

#[doc(hidden)]
pub use next_core as __next_core;

/// Runs the tests `tests` returns. Call it first in `main`.
pub fn run(tests: impl FnOnce() -> Vec<Test>) -> ExitCode {
    // Helpers are this binary started again: they run their function in here
    // and exit, so nothing below runs in them.
    procspawn::ProcConfig::new().pass_args(false).init();
    // SAFETY: helpers are functions linked into this executable, never of a
    // shared library, so their offset from `init` is the same in every process.
    unsafe { procspawn::assert_spawn_is_safe() };

    if std::process::id() == 1 {
        return vm::init();
    }
    env_logger::init();
    let mut args = libtest_mimic::Arguments::from_args();
    // Tests share the pin directory.
    args.test_threads = Some(1);
    libtest_mimic::run(&args, outcome::trials(tests())).exit_code()
}
