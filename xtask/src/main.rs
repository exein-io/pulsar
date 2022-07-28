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
    match task.as_ref().map(|it| it.as_str()) {
        Some("test") => test(args)?,
        _ => print_help(),
    }
    Ok(())
}

fn print_help() {
    eprintln!(
        "Tasks:
test            run eBPF test suite with admin priviledges
"
    )
}

fn test(args: Args) -> Result<()> {
    let sh = Shell::new()?;
    cmd!(sh, "cargo build --bin test-suite").run()?;
    cmd!(sh, "sudo ./target/debug/test-suite {args...}").run()?;
    Ok(())
}
