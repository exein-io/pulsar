use std::path::PathBuf;

use engine::RuleEngine;
use pulsar_core::pdk::{
    ConfigError, Event, ModuleConfig, ModuleContext, ModuleError, SimplePulsarModule,
};

mod dsl;
mod engine;
mod ruleset;

pub use engine::RuleEngineData;

const DEFAULT_RULES_PATH: &str = "/var/lib/pulsar/rules";

pub struct RuleEngineModule;

impl SimplePulsarModule for RuleEngineModule {
    type Config = Config;
    type State = State;

    const MODULE_NAME: &'static str = "rules-engine";
    const DEFAULT_ENABLED: bool = true;

    async fn init_state(
        &self,
        config: &Self::Config,
        ctx: &ModuleContext,
    ) -> Result<Self::State, ModuleError> {
        Ok(Self::State {
            engine: RuleEngine::new(&config.rules_path, ctx.clone())?,
        })
    }

    async fn on_config_change(
        new_config: &Self::Config,
        state: &mut Self::State,
        ctx: &ModuleContext,
    ) -> Result<(), ModuleError> {
        state.engine = RuleEngine::new(&new_config.rules_path, ctx.clone())?;
        Ok(())
    }

    async fn on_event(
        event: &Event,
        _config: &Self::Config,
        state: &mut Self::State,
        _ctx: &ModuleContext,
    ) -> Result<(), ModuleError> {
        state.engine.process(event);
        Ok(())
    }
}

pub struct State {
    engine: RuleEngine,
}

#[derive(Clone)]
pub struct Config {
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
