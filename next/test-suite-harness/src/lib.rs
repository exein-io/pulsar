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

use serde::{Serialize, de::DeserializeOwned};

pub use outcome::{Outcome, Test, TestResult, Verdict};

use crate::{
    daemon::{Recording, TestDaemon},
    helper::Helper,
};

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

/// What [`watch`] returns.
pub struct Watched<R> {
    pub recording: Recording,
    /// The pid of the helper.
    pub pid: u32,
    /// What the function of the helper returned.
    pub result: R,
}

/// Runs `f(args)` in a helper, see [`Helper::spawn`], while a daemon with
/// the OSS probes watches. The recording ends with the exit of the helper.
pub async fn watch<A, R, F>(args: A, f: F) -> anyhow::Result<Watched<R>>
where
    A: Serialize + DeserializeOwned,
    R: Serialize + DeserializeOwned + Send + 'static,
    F: Fn(A) -> R,
{
    let helper = Helper::spawn(args, f)?;
    let daemon = TestDaemon::start().await?;
    let pid = helper.pid();
    let result = helper.finish().await?;
    let recording = daemon.stop_after_exit(pid).await?;
    Ok(Watched {
        recording,
        pid,
        result,
    })
}
