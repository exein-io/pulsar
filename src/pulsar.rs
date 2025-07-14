use anyhow::{Context, Result, ensure};
use clap::{ArgGroup, Args, Parser, Subcommand};
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

    /// Manage module configuration
    Config(Config),

    /// Start event monitor
    Monitor(Monitor),
}

// THIS "SHIM" STRUCT IS MANDATORY
#[derive(Parser, Debug, Clone)]
#[clap(group(
    ArgGroup::new("config_variant")
        .required(true)
        .args(&["all", "module", "set"]),
))]
pub struct Config {
    /// Print configuration for all modules
    #[clap(long, short)]
    pub all: bool,

    /// Print configuration for a specified module
    #[clap(long, short)]
    pub module: Option<String>,

    /// Set/Update configuration for a specified module: syntax is 'MODULE.KEY=VALUE'
    #[clap(long, short, value_parser=parse_mc_key_value, value_name = "MODULE.KEY=VALUE")]
    pub set: Option<ModuleConfigKV>,
}

#[derive(Parser, Debug, Clone)]
pub struct ModuleConfigKV {
    pub module_name: String,
    pub key: String,
    pub value: String,
}

#[derive(Parser, Debug, Clone)]
pub struct Monitor {
    /// Show all events
    #[clap(long, default_value_t = false)]
    pub all: bool,
}

fn parse_mc_key_value(input: &str) -> Result<ModuleConfigKV> {
    // split 'module_name.config_name=config_value'
    let parts: Vec<&str> = input.split('=').filter(|s| !s.is_empty()).collect();
    ensure!(
        parts.len() == 2,
        "invalid configuration expression '{}': syntax is 'MODULE.KEY=VALUE'",
        input
    );
    let (module_and_config, value) = (parts[0], parts[1]);

    // split 'module_name.config_name'
    let parts: Vec<&str> = module_and_config
        .split('.')
        .filter(|s| !s.is_empty())
        .collect();
    ensure!(
        parts.len() == 2,
        "invalid module expression '{}': syntax is 'MODULE.KEY=VALUE'",
        module_and_config
    );
    let (module_name, key) = (parts[0], parts[1]);

    Ok(ModuleConfigKV {
        module_name: module_name.to_string(),
        key: key.to_string(),
        value: value.to_string(),
    })
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
        Commands::Config(Config { all, module, set }) => match (all, module, set) {
            (true, _, _) => engine_api_client.get_configs().await?.term_print(),
            (_, Some(module), _) => engine_api_client
                .get_module_config(module)
                .await?
                .term_print(),
            (
                _,
                _,
                Some(ModuleConfigKV {
                    module_name,
                    key,
                    value,
                }),
            ) => {
                engine_api_client
                    .set_module_config(module_name, key.clone(), value.clone())
                    .await?;
                "Configuration updated".to_string().term_print()
            }
            _ => unreachable!(),
        },
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
