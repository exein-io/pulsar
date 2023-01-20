use anyhow::Result;
use pulsar::cli;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse cli and handle clap errors
    let options = cli::parse_from_args();

    // Override the default log_level if there is a greater verbosity flag
    pulsar::init_logger(options.override_log_level);

    // Run pulsar-exec with crate provided modules
    match pulsar::run_pulsar_exec(&options, pulsar::modules()).await {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            cli::report_error(&e);
            std::process::exit(1);
        }
    }
}
