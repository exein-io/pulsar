use anyhow::Result;
use clap::Parser;
use xshell::{cmd, Shell};

#[derive(Debug, Parser)]
pub(crate) struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    /// Build binary and copy it to destination folder
    Build {
        /// Where to copy the file
        #[clap(long, default_value = "/tmp/")]
        destination: String,

        #[command(flatten)]
        opts: SharedOptions,
    },
    /// Run over the given SSH connection.
    Run {
        /// Target ssh
        #[clap(long, default_value = "qemu")]
        ssh_target: String,

        /// Arguments passed on process execution
        args: Vec<String>,

        #[command(flatten)]
        opts: SharedOptions,
    },
}

#[derive(Debug, Parser)]
struct SharedOptions {
    /// Target architecture
    #[clap(long, default_value = "x86_64-unknown-linux-musl")]
    target: String,

    /// Binary to compile
    #[clap(long, default_value = "test-suite")]
    binary: String,

    /// Build and run the release target
    #[clap(long)]
    release: bool,
}

pub(crate) fn run(options: Options) -> Result<()> {
    let sh = Shell::new()?;
    let SharedOptions {
        target,
        binary,
        release,
    } = match &options.command {
        Command::Build { opts, .. } => opts,
        Command::Run { opts, .. } => opts,
    };
    let args = if *release { Some("--release") } else { None };
    cmd!(
        sh,
        "cross build --target {target} --target-dir target/cross --workspace --bin {binary} {args...}"
    )
    .run()?;
    let build_type = if *release { "release" } else { "debug" };
    let binary_file = format!("target/cross/{target}/{build_type}/{binary}");
    cmd!(sh, "llvm-strip {binary_file}").run()?;
    match &options.command {
        Command::Build {
            destination,
            opts: _,
        } => cmd!(sh, "cp {binary_file} {destination}").run()?,
        Command::Run {
            ssh_target,
            args,
            opts: _,
        } => {
            cmd!(sh, "scp {binary_file} {ssh_target}:/tmp/").run()?;
            cmd!(sh, "ssh {ssh_target} /tmp/{binary} {args...}").run()?;
        }
    }
    Ok(())
}
