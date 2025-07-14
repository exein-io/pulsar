use anyhow::Result;
use clap::Parser;
use clap_verbosity_flag::{InfoLevel, Verbosity};
use pulsar::pulsard::PulsarDaemonOpts;

#[path = "_common/clap_version.rs"]
mod clap_version;

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    pulsar::init_logger(Some(opts.verbosity.log_level_filter()));

    match pulsar::pulsard::pulsar_daemon_run(&opts.daemon_opts, |_| Ok(())).await {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            pulsar::utils::report_error(&e);
            std::process::exit(1);
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[clap(about = "Pulsar runtime security agent")]
#[clap(version = clap_version::pulsar_clap_version())]
#[clap(disable_help_subcommand = true)]
struct Opts {
    #[command(flatten)]
    pub daemon_opts: PulsarDaemonOpts,

    #[command(flatten)]
    pub verbosity: Verbosity<InfoLevel>,
}
