use std::path::PathBuf;

use engine::PulsarEngine;
use pulsar_core::pdk::{
    CleanExit, ConfigError, ModuleConfig, ModuleContext, ModuleError, PulsarModule, ShutdownSignal,
    Version,
};

mod engine;

const DEFAULT_RULES_PATH: &str = "/var/lib/pulsar/rules";
const MODULE_NAME: &str = "rules-engine";

pub fn module() -> PulsarModule {
    PulsarModule::new(MODULE_NAME, Version::new(0, 0, 1), rules_engine_task)
}

async fn rules_engine_task(
    ctx: ModuleContext,
    mut shutdown: ShutdownSignal,
) -> Result<CleanExit, ModuleError> {
    let mut receiver = ctx.get_receiver();
    let mut rx_config = ctx.get_cfg::<Config>();

    let mut engine = PulsarEngine::new(&rx_config.borrow().clone()?.rules_path, ctx.get_sender())?;

    loop {
        tokio::select! {
            r = shutdown.recv() => return r,
            _ = rx_config.changed() => {
                engine = PulsarEngine::new(&rx_config.borrow().clone()?.rules_path, ctx.get_sender())?;
            }
            // handle pulsar message
            event = receiver.recv() => {
                let event = event?;
                    engine.process(&event)

            },
        }
    }
}

#[derive(Clone)]
struct Config {
    rules_path: PathBuf,
}

impl TryFrom<&ModuleConfig> for Config {
    type Error = ConfigError;

    fn try_from(config: &ModuleConfig) -> Result<Self, Self::Error> {
        let rules_path = config.with_default("rules_path", PathBuf::from(DEFAULT_RULES_PATH))?;

        if !rules_path.exists() {
            return Err(ConfigError::InvalidValue {
                field: "rules_path".to_string(),
                value: rules_path.display().to_string(),
                err: format!("Directory '{}' not exists", rules_path.display()),
            });
        }

        Ok(Self { rules_path })
    }
}
