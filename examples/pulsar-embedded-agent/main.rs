use anyhow::{Context, Result};
use pulsar::{cli, TaskLauncher};
use pulsar_core::pdk::ModuleContext;
use tokio::sync::oneshot;

mod proxy_module;

#[tokio::main]
async fn main() -> Result<()> {
    let context = spawn_pulsar().await?;
    let pulsar_daemon = context.get_daemon_handle();

    // Stop a module
    pulsar_daemon.stop("network-monitor".to_string()).await?;

    // Change configuration
    pulsar_daemon
        .update_configuration(
            "network-monitor".to_string(),
            "enabled".to_string(),
            "false".to_string(),
        )
        .await?;

    // Read events
    let mut event_receiver = context.get_receiver();
    while let Ok(event) = event_receiver.recv().await {
        println!("{event:?}");
    }
    Ok(())
}

async fn spawn_pulsar() -> Result<ModuleContext> {
    let options = cli::PulsarExecOpts {
        mode: cli::Mode::PulsarDaemon(cli::pulsard::PulsarDaemonOpts { config_file: None }),
        override_log_level: log::Level::Info,
    };

    // Add a custom module used to proxy comunication between Pulsar and the rest
    // of the application.
    let (tx_ctx, rx_ctx) = oneshot::channel();
    let mut modules = pulsar::modules();
    modules.push(Box::new(proxy_module::module(tx_ctx)) as Box<dyn TaskLauncher>);

    tokio::spawn(async move {
        // Run pulsar-exec with crate provided modules
        match pulsar::run_pulsar_exec(&options, modules).await {
            Ok(_) => std::process::exit(0),
            Err(e) => {
                cli::report_error(&e);
                std::process::exit(1);
            }
        }
    });

    rx_ctx.await.context("Getting context failed")
}
