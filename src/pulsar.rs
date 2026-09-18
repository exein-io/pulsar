use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use engine_api::client::EngineApiClient;
use futures_util::StreamExt;

mod term_print;

use crate::pulsar::term_print::TermPrintable;

#[derive(Args, Debug, Clone)]
// #[clap(name = "pulsar")]
// #[clap(about = "Pulsar cli")]
// #[clap(version = pulsar_clap_version())]
pub struct PulsarCliOpts {
    /// Specify custom api server
    #[clap(long)]
    pub api_server: Option<String>,

    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    /// Modules status
    Status,

    /// Start a module
    Start { module_name: String },

    /// Restart a module
    Restart { module_name: String },

    /// Stop a module
    Stop { module_name: String },

    /// Start event monitor
    Monitor(Monitor),
}

// THIS "SHIM" STRUCT IS MANDATORY
#[derive(Parser, Debug, Clone)]
pub struct Monitor {
    /// Show all events
    #[clap(long, default_value_t = false)]
    pub all: bool,
}

pub async fn pulsar_cli_run(options: &PulsarCliOpts) -> Result<()> {
    log::trace!("Pulsar CLI Options: {:?}", options);

    let engine_api_client = if let Some(api_server) = &options.api_server {
        EngineApiClient::unix(api_server.clone())?
    } else {
        EngineApiClient::new()?
    };

    log::trace!("Command received: {:?}", options.command);

    match &options.command {
        Commands::Status => engine_api_client.list_modules().await?.term_print(),
        Commands::Start { module_name } => {
            engine_api_client.start(module_name).await?;
            "Module starting".to_string().term_print()
        }
        Commands::Restart { module_name } => {
            engine_api_client.restart(module_name).await?;
            "Module restarting".to_string().term_print()
        }
        Commands::Stop { module_name } => {
            engine_api_client.stop(module_name).await?;
            "Module stopped".to_string().term_print()
        }
        Commands::Monitor(Monitor { all }) => {
            let mut stream = engine_api_client.event_monitor().await?;

            while let Some(ws_read) = stream.next().await {
                match ws_read {
                    Ok(event) => {
                        if *all || event.header().threat.is_some() {
                            println!("{event:#}");
                        }
                    }
                    Err(e) => return Err(e).context("error reading from websocket"),
                }
            }

            Err(anyhow::anyhow!("event stream ended"))
        }
    }?;

    Ok(())
}
