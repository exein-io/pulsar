// TODO: use specific configuration key instead ok target_os and target_arch

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "platform/linux-x86_64.rs"]
mod platform;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[path = "platform/linux-aarch64.rs"]
mod platform;

#[cfg(all(target_os = "linux", target_arch = "riscv64"))]
#[path = "platform/linux-riscv64.rs"]
mod platform;

pub use platform::*;
