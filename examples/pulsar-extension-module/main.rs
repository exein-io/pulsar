mod my_custom_module;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse cli and handle clap errors
    let options = pulsar::cli::parse_from_args();

    // Override the default log_level if there is a greater verbosity flag
    pulsar::init_logger(options.override_log_level);

    // Run pulsar-exec with the additional module
    #[allow(clippy::blocks_in_conditions)]
    match pulsar::run_pulsar_exec_custom(&options, |starter| {
        starter.add_module(my_custom_module::MyCustomModule)?;

        Ok(())
    })
    .await
    {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            pulsar::cli::report_error(&e);
            std::process::exit(1);
        }
    }
}
