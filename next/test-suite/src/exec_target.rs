//! What tests exec: not the suite, so an exec changes the image.
//!
//! It exits at once, unless its first argument is [`FORK_LOOP`]: then it forks
//! children that exit at once, until it is killed.

use nix::{
    sys::wait::waitpid,
    unistd::{ForkResult, fork},
};

/// The same as in `process.rs`.
const FORK_LOOP: &str = "fork-loop";

fn main() {
    if std::env::args_os()
        .nth(1)
        .is_none_or(|arg| arg != FORK_LOOP)
    {
        return;
    }
    loop {
        // SAFETY: the process has a single thread, so the child may run any
        // code.
        match unsafe { fork() }.expect("fork") {
            ForkResult::Child => std::process::exit(0),
            ForkResult::Parent { child } => {
                waitpid(child, None).expect("waiting for a child");
            }
        }
    }
}
