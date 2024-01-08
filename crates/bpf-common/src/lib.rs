mod bpf_sender;
pub mod containers;
pub mod program;
#[cfg(feature = "test-utils")]
pub mod test_runner;
#[cfg(feature = "test-utils")]
pub mod test_utils;

#[cfg(debug_assertions)]
pub mod trace_pipe;

mod bump_memlock_rlimit;
pub mod parsing;
pub mod time;

pub use bpf_sender::{BpfSender, BpfSenderWrapper};
pub use bump_memlock_rlimit::bump_memlock_rlimit;
pub use program::{Program, ProgramBuilder, ProgramError};

pub use aya;

pub mod bpf_fs;
pub mod feature_autodetect;

/// Utility function to pretty print an error with its sources.
///
/// We use this because by default Rust won't print the source of an error message,
/// making it much less useful. Instead of re-implementing that, we'll just use
/// anyhow as an error pretty-printer.
pub fn log_error<E: std::error::Error + Send + Sync + 'static>(msg: &str, err: E) {
    log::error!("{}: {:?}", msg, anyhow::Error::from(err));
}

pub use nix::unistd::Pid;

#[cfg(all(target_os = "linux", target_arch = "x86"))]
#[path = "platform/linux-x86/mod.rs"]
pub mod platform;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "platform/linux-x86_64/mod.rs"]
pub mod platform;

#[cfg(all(target_os = "linux", target_arch = "arm"))]
#[path = "platform/linux-armeabi/mod.rs"]
pub mod platform;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[path = "platform/linux-aarch64/mod.rs"]
pub mod platform;

#[cfg(all(target_os = "linux", target_arch = "riscv64"))]
#[path = "platform/linux-riscv64/mod.rs"]
pub mod platform;

pub const MAX_SYSCALLS: usize = 512;
