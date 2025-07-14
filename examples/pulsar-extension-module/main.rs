use clap::Parser;
use clap_verbosity_flag::{InfoLevel, Verbosity};
use pulsar::pulsard::PulsarDaemonOpts;

mod my_custom_module;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse cli and handle clap errors
    let options = Opts::parse();

    // Override the default log_level if there is a greater verbosity flag
    pulsar::init_logger(Some(options.verbosity.log_level_filter()));

    // Run pulsard with the additional module
    #[allow(clippy::blocks_in_conditions)]
    match pulsar::pulsard::pulsar_daemon_run(&options.daemon_opts, |starter| {
        starter.add_module(my_custom_module::MyCustomModule)?;

        Ok(())
    })
    .await
    {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            pulsar::utils::report_error(&e);
            std::process::exit(1);
        }
    }
}

#[derive(Debug, Parser)]
struct Opts {
    #[command(flatten)]
    daemon_opts: PulsarDaemonOpts,

    #[command(flatten)]
    pub verbosity: Verbosity<InfoLevel>,
}
