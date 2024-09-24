use clap::Parser;
use signal_hook::{consts::TERM_SIGNALS, iterator::Signals};
use xtask::surun::SuRunCommand;

mod tempdir;
mod test_suite;
mod vmlinux;

#[derive(Debug, Parser)]
#[clap(disable_help_subcommand = true)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    /// Same as `cargo run` but with admin privileges (using `sudo -E` as runner)
    #[clap(name = "surun")]
    SuRun(SuRunCommand),
    /// Run eBPF test suite with admin privileges
    TestSuite(test_suite::Options),
    /// Build headers with BTF type definitions.
    Vmlinux(vmlinux::Options),
}

fn main() {
    let opts = Options::parse();

    env_logger::init();

    // Drop term signals: register a handler, but never check it
    let _ = Signals::new(TERM_SIGNALS).expect("error setting signal handler");

    let ret = match opts.command {
        Command::SuRun(cmd) => cmd.run(),
        Command::TestSuite(opts) => test_suite::run(opts),
        Command::Vmlinux(opts) => vmlinux::run(opts),
    };

    if let Err(e) = ret {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
