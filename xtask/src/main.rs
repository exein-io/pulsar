use std::env;

use anyhow::Result;
use xshell::{cmd, Shell};

fn main() {
    if let Err(e) = try_main() {
        eprintln!("{}", e);
        std::process::exit(-1);
    }
}

fn try_main() -> Result<()> {
    let task = env::args().nth(1);
    match task.as_ref().map(|it| it.as_str()) {
        Some("test") => test()?,
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

fn test() -> Result<()> {
    let sh = Shell::new()?;
    // TODO: make generic
    cmd!(sh, "cargo build --bin test-suite").run()?;
    cmd!(sh, "sudo ./target/debug/test-suite").run()?;
    Ok(())
}
