//! Running as the init of a VM (see `vm.sh`): mount what a booted system would
//! have, run the suite as a child, print its exit code and power off.

use std::{fs, process::Command};

use anyhow::Context;
use nix::{
    mount::{MsFlags, mount},
    sys::reboot::{RebootMode, reboot},
};

/// `vm.sh` reads the exit code of the suite from the line starting with this.
const EXIT_LINE: &str = "test-suite-next exit code:";

/// File system types and where they go.
const MOUNTS: &[(&str, &str)] = &[
    ("proc", "/proc"),
    ("sysfs", "/sys"),
    ("bpf", "/sys/fs/bpf"),
    ("cgroup2", "/sys/fs/cgroup"),
];

pub fn init() -> std::process::ExitCode {
    let code = run().unwrap_or_else(|err| {
        eprintln!("{err:#}");
        1
    });
    println!("{EXIT_LINE} {code}");
    // If this fails, init exits, the kernel panics and the VM stops anyway.
    let Err(err) = reboot(RebootMode::RB_POWER_OFF);
    eprintln!("powering off: {err}");
    std::process::ExitCode::FAILURE
}

fn run() -> anyhow::Result<i32> {
    for (fstype, target) in MOUNTS {
        fs::create_dir_all(target)?;
        mount(
            Some(*fstype),
            *target,
            Some(*fstype),
            MsFlags::empty(),
            None::<&str>,
        )
        .with_context(|| format!("mounting {fstype} on {target}"))?;
    }
    // procspawn keeps its sockets there.
    fs::create_dir_all(std::env::temp_dir())?;
    let status = Command::new(std::env::current_exe()?)
        .args(std::env::args_os().skip(1))
        .status()?;
    eprintln!("test-suite-next: {status}");
    Ok(status.code().unwrap_or(1))
}
