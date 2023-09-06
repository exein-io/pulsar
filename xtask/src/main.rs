use clap::Parser;
use run::run_with_sudo;
use signal_hook::{consts::TERM_SIGNALS, iterator::Signals};

mod cross;
mod run;
mod vmlinux;

#[derive(Debug, Parser)]
#[clap(disable_help_subcommand = true)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    /// Run pulsar daemon with admin privileges
    Pulsard(run::Options),
    /// Run pulsar cli with admin privileges
    Pulsar(run::Options),
    /// Run a single module with admin privileges
    Probe(run::Options),
    /// Run eBPF test suite with admin privileges
    Test(run::Options),
    /// Cross compile and run on the specified target
    Cross(cross::Options),
    /// Build headers with BTF type definitions.
    Vmlinux(vmlinux::Options),
}

fn main() {
    let opts = Options::parse();

    // Drop term signals: register a handler, but never check it
    let _ = Signals::new(TERM_SIGNALS).expect("error setting signal handler");

    let ret = match opts.command {
        Command::Pulsard(opts) => run_with_sudo("pulsar-exec", &["pulsard"], opts),
        Command::Pulsar(opts) => run_with_sudo("pulsar-exec", &["pulsar"], opts),
        Command::Probe(opts) => run_with_sudo("probe", &[], opts),
        Command::Test(opts) => run_with_sudo("test-suite", &[], opts),
        Command::Cross(opts) => cross::run(opts),
        Command::Vmlinux(opts) => vmlinux::run(opts),
    };

    if let Err(e) = ret {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
