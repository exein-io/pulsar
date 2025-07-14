use anyhow::Result;
use pulsar::{pulsard, utils};
use tokio::sync::mpsc::{self};

mod proxy_module;

#[tokio::main]
async fn main() -> Result<()> {
    // Add a custom module used to proxy comunication between Pulsar and the rest
    // of the application.
    let (tx_proxy, mut rx_proxy) = mpsc::channel(100);

    let options = pulsard::PulsarDaemonOpts { config_file: None };

    tokio::spawn(async move {
        // Run pulsard with crate-provided modules
        #[allow(clippy::blocks_in_conditions)]
        match pulsar::pulsard::pulsar_daemon_run(&options, move |starter| {
            starter.add_module(proxy_module::ProxyModule { tx_proxy })?;

            Ok(())
        })
        .await
        {
            Ok(_) => std::process::exit(0),
            Err(e) => {
                utils::report_error(&e);
                std::process::exit(1);
            }
        }
    });

    // Read events
    while let Some(event) = rx_proxy.recv().await {
        println!("{event:?}");
    }
    Ok(())
}
