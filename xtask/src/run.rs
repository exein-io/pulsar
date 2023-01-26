use anyhow::Result;
use clap::Parser;
use xshell::{cmd, Shell};

#[derive(Debug, Parser)]
pub struct Options {
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
    /// Arguments to pass to your application
    #[clap(name = "args")]
    pub run_args: Vec<String>,
}

/// Build the binary
fn build(package: &str, binary: &str, opts: &Options) -> Result<()> {
    let sh = Shell::new()?;
    let cargo = std::env::var("CARGO").unwrap();
    let args = if opts.release {
        Some("--release")
    } else {
        None
    };
    cmd!(
        sh,
        "{cargo} build --package {package} --bin {binary} {args...}"
    )
    .run()?;

    Ok(())
}

/// Build and run the binary with admin privileges
pub fn run_with_sudo(package: &str, binary: &str, prefix: &[&str], opts: Options) -> Result<()> {
    build(package, binary, &opts)?;

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
