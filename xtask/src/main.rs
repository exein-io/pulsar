use std::env::{self, Args};

use anyhow::Result;
use xshell::{cmd, Shell};

fn main() {
    if let Err(e) = try_main() {
        eprintln!("{}", e);
        std::process::exit(-1);
    }
}

fn try_main() -> Result<()> {
    let mut args = env::args();
    let task = args.nth(1);
    match task.as_deref() {
        Some("test") => run_with_sudo("test-suite", &[], args)?,
        Some("pulsard") => run_with_sudo("pulsar-exec", &["pulsard"], args)?,
        Some("pulsar") => run_with_sudo("pulsar-exec", &["pulsar"], args)?,
        Some("probe") => run_with_sudo("probe", &[], args)?,
        _ => print_help(),
    }
    Ok(())
}

fn print_help() {
    eprintln!(
        "Tasks:
test            run eBPF test suite with admin privileges
pulsard         run pulsar agent daemon with admin privileges
pulsar          run pulsar agent client with admin privileges
probe           run a single module with admin privileges
"
    )
}

fn run_with_sudo(binary: &str, prefix: &[&str], args: Args) -> Result<()> {
    let sh = Shell::new()?;
    cmd!(sh, "cargo build --bin {binary}").run()?;
    // -E preserves the environment
    cmd!(sh, "sudo -E ./target/debug/{binary} {prefix...} {args...}").run()?;
    Ok(())
}
