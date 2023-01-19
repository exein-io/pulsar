use anyhow::Result;
use clap::Parser;
use xshell::{cmd, Shell};

#[derive(Debug, Parser)]
pub struct Options {
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
    /// Arguments to pass to your application
    #[clap(name = "args", last = true)]
    pub run_args: Vec<String>,
}

/// Build the binary
fn build(binary: &str, opts: &Options) -> Result<()> {
    let sh = Shell::new()?;

    let mut build_cmd = format!("cargo build --bin {binary}");
    if opts.release {
        build_cmd.push_str(" --release")
    }
    cmd!(sh, "{build_cmd}").run()?;

    Ok(())
}

/// Build and run the binary with admin privileges
pub fn run_with_sudo(binary: &str, prefix: &[&str], opts: Options) -> Result<()> {
    build(binary, &opts)?;

    let sh = Shell::new()?;

    let target = if opts.release { "release" } else { "debug" };
    let args = opts.run_args;
    // -E preserves the environment
    cmd!(
        sh,
        "sudo -E ./target/{target}/{binary} {prefix...} {args...}"
    )
    .run()?;

    Ok(())
}
