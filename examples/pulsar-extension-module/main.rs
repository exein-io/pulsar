use pulsar_core::pdk::Module;

mod my_custom_module;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse cli and handle clap errors
    let options = pulsar::cli::parse_from_args();

    // Override the default log_level if there is a greater verbosity flag
    pulsar::init_logger(options.override_log_level);

    // Get all pulsar modules and append our custom ones
    let mut modules = pulsar::modules();
    modules.push(<my_custom_module::MyCustomModule as Module>::start());

    // Run pulsar-exec with crate provided modules
    match pulsar::run_pulsar_exec(&options, modules).await {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            pulsar::cli::report_error(&e);
            std::process::exit(1);
        }
    }
}
