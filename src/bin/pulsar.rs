use anyhow::Result;
use clap::Parser;
use clap_verbosity_flag::{InfoLevel, Verbosity};
use pulsar::pulsar::PulsarCliOpts;

#[path = "_common/clap_version.rs"]
mod clap_version;

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    pulsar::init_logger(Some(opts.verbosity.log_level_filter()));

    match pulsar::pulsar::pulsar_cli_run(&opts.cli_opts).await {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            pulsar::utils::report_error(&e);
            std::process::exit(1);
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[clap(about = "Pulsar command line utility")]
#[clap(version = clap_version::pulsar_clap_version())]
#[clap(disable_help_subcommand = true)]
struct Opts {
    #[command(flatten)]
    cli_opts: PulsarCliOpts,

    #[command(flatten)]
    pub verbosity: Verbosity<InfoLevel>,
}
