use anyhow::Result;
use engine_api::client::EngineApiClient;

mod pretty_print;

use crate::{
    cli::pulsar::{Commands, Config, ModuleConfigKV, PulsarCliOpts},
    pulsar::pretty_print::TermPrintable,
};

pub async fn pulsar_cli_run(options: &PulsarCliOpts) -> Result<()> {
    // TODO: ownership of PulsarCliOpts
    log::trace!("Pulsar CLI Options: {:?}", options);

    let engine_api_client = if let Some(api_server) = &options.api_server {
        EngineApiClient::unix(api_server.clone())?
    } else {
        EngineApiClient::default()?
    };

    log::trace!("Command received: {:?}", options.command);

    match &options.command {
        Commands::Status => engine_api_client.list_modules().await?.term_print(),
        Commands::Start { module_name } => {
            engine_api_client.start(module_name).await?;
            "Module started".to_string().term_print()
        }
        Commands::Restart { module_name } => {
            engine_api_client.restart(module_name).await?;
            "Module restarted".to_string().term_print()
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
    }?;

    Ok(())
}
