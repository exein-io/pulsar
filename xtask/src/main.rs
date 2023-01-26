use clap::Parser;
use run::run_with_sudo;

mod run;

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
}

fn main() {
    let opts = Options::parse();

    let ret = match opts.command {
        Command::Pulsard(opts) => run_with_sudo("pulsar", "pulsar-exec", &["pulsard"], opts),
        Command::Pulsar(opts) => run_with_sudo("pulsar", "pulsar-exec", &["pulsar"], opts),
        Command::Probe(opts) => run_with_sudo("pulsar", "probe", &[], opts),
        Command::Test(opts) => run_with_sudo("test-suite", "test-suite", &[], opts),
    };

    if let Err(e) = ret {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
