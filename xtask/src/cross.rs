use anyhow::Result;
use clap::Parser;
use xshell::{cmd, Shell};

#[derive(Debug, Parser)]
pub(crate) struct Options {
    /// Target architecture
    #[clap(long, default_value = "x86_64-unknown-linux-musl")]
    pub(crate) target: String,

    /// Binary to compile
    #[clap(long, default_value = "test-suite")]
    pub(crate) binary: String,

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
    },
    /// Run over the given SSH connection.
    Run {
        /// Target ssh
        #[clap(long, default_value = "qemu")]
        ssh_target: String,
        /// Arguments passed on process execution
        args: Vec<String>,
    },
}

pub(crate) fn run(options: Options) -> Result<()> {
    let sh = Shell::new()?;
    let Options {
        target,
        binary,
        command,
    } = options;
    cmd!(
        sh,
        "cross build --target {target} --workspace --bin {binary}"
    )
    .run()?;
    let binary_file = format!("target/{target}/debug/{binary}");
    cmd!(sh, "llvm-strip {binary_file}").run()?;
    match command {
        Command::Build { destination } => cmd!(sh, "cp {binary_file} {destination}").run()?,
        Command::Run { ssh_target, args } => {
            cmd!(sh, "scp {binary_file} {ssh_target}:/tmp/").run()?;
            cmd!(sh, "ssh {ssh_target} /tmp/{binary} {args...}").run()?;
        }
    }
    Ok(())
}
