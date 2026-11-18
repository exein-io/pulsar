//! Tests of `probes/process.bpf.c`.

use nix::sys::wait::waitpid;

use next_test_suite_harness::{
    Test, TestResult,
    daemon::TestDaemon,
    expect::expect,
    helper::{self, Helper},
    pattern::{Exit, Fork},
};

pub fn tests() -> Vec<Test> {
    vec![Test::new("fork_exit", || Box::pin(fork_exit()))]
}

/// A child of the helper exits with a known code.
async fn fork_exit() -> TestResult {
    const EXIT_CODE: i32 = 42;
    let helper = Helper::spawn((), |()| {
        let child = helper::fork(|| EXIT_CODE);
        waitpid(child, None).expect("waiting for the child");
        child.as_raw() as u32
    })?;
    let daemon = TestDaemon::start().await?;
    let parent = helper.pid();
    let child = helper.finish().await?;
    let recording = daemon.stop_after_exit(parent).await?;

    let image = std::env::current_exe()?.to_string_lossy().into_owned();
    Ok(expect(
        &recording,
        &[
            &Fork::of(child)
                .ppid(parent)
                .header(|header| header.image(image)),
            &Exit::of(child).exit_code(EXIT_CODE as u32),
        ],
    ))
}
