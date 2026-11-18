//! Helpers: the processes a test acts through.
//!
//! The suite runs on a multithreaded runtime, so it must never fork: the child
//! of a multithreaded process may only call async-signal-safe functions. A
//! helper is this binary started again by procspawn, a single-threaded process
//! that runs one function and exits. In there any code is fine, [`fork`]
//! included.

use std::{fs, time::Duration};

use anyhow::Context;
use ipc_channel::ipc::{self, IpcReceiver, IpcSender};
use nix::unistd::{ForkResult, Pid};
use serde::{Serialize, de::DeserializeOwned};

/// How long a helper may run after [`Helper::finish`] let it go, unless the
/// test sets its own with [`Helper::run_timeout`].
const DEFAULT_RUN_TIMEOUT: Duration = Duration::from_secs(10);

/// A helper process. Dropping it kills the process.
pub struct Helper<R> {
    process: procspawn::JoinHandle<R>,
    /// The helper waits for a message on it before running its function.
    go: IpcSender<()>,
    pid: u32,
    run_timeout: Duration,
}

impl<R: Serialize + DeserializeOwned + Send + 'static> Helper<R> {
    /// Starts a process that runs `f(args)` once [`finish`](Self::finish)
    /// lets it go. Start helpers before the daemon, so their own start isn't
    /// observed.
    ///
    /// `f` runs in that process, so it can't capture anything: what it needs
    /// goes in `args`.
    pub fn spawn<A, F>(args: A, _f: F) -> anyhow::Result<Self>
    where
        A: Serialize + DeserializeOwned,
        F: Fn(A) -> R,
    {
        const {
            assert!(
                size_of::<F>() == 0,
                "a helper's function can't capture anything: pass it in `args`"
            )
        };
        let (go, wait) = ipc::channel()?;
        let process = procspawn::spawn((wait, args), run::<A, R, F>);
        let pid = process.pid().context("starting a helper")?;
        Ok(Self {
            process,
            go,
            pid,
            run_timeout: DEFAULT_RUN_TIMEOUT,
        })
    }

    pub fn run_timeout(mut self, timeout: Duration) -> Self {
        self.run_timeout = timeout;
        self
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Lets the helper go on, and returns what its function returned, once
    /// the process exited.
    pub async fn finish(self) -> anyhow::Result<R> {
        let Self {
            mut process,
            go,
            run_timeout,
            ..
        } = self;
        go.send(())?;
        let result = tokio::task::spawn_blocking(move || process.join_timeout(run_timeout)).await?;
        Ok(result?)
    }
}

/// What procspawn runs in a helper. procspawn takes a function pointer, not a
/// closure, so the test's `f` can't reach the helper. Instead, `run` is made
/// for the type of `f`: `f` captures nothing, so its type alone is enough to
/// make it again.
fn run<A, R, F: Fn(A) -> R>((go, args): (IpcReceiver<()>, A)) -> R {
    go.recv().expect("the test went away");
    // SAFETY: `F` is zero-sized (checked in `Helper::spawn`), so it holds no
    // data: a value made from nothing is the same as the test's `f`.
    let f: F = unsafe { std::mem::zeroed() };
    f(args)
}

/// Forks the helper. The child runs `child` and exits with the code it
/// returns.
pub fn fork(child: impl FnOnce() -> i32) -> Pid {
    let threads = fs::read_dir("/proc/self/task").map(Iterator::count);
    assert!(
        matches!(threads, Ok(1)),
        "only a single-threaded helper may fork"
    );
    // SAFETY: the process has a single thread, so the child may run any code.
    match unsafe { nix::unistd::fork() }.expect("fork") {
        ForkResult::Child => std::process::exit(child()),
        ForkResult::Parent { child } => child,
    }
}
