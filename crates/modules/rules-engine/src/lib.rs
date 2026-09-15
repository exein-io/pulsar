use std::path::PathBuf;

use engine::RuleEngine;
use pulsar_core::pdk::{Event, ModuleContext, ModuleError, SimplePulsarModule};
use serde::Deserialize;

mod dsl;
mod engine;
mod ruleset;

pub use engine::{Category, Metadata, Severity};

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
        if !config.rules_path.is_dir() {
            return Err(format!(
                "rules_path '{}' is not a directory",
                config.rules_path.display()
            )
            .into());
        }

        Ok(Self::State {
            engine: RuleEngine::new(&config.rules_path, ctx.clone())?,
        })
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

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Directory scanned recursively for rule files.
    rules_path: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rules_path: PathBuf::from(DEFAULT_RULES_PATH),
        }
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn missing_keys_keep_defaults() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.rules_path, PathBuf::from(DEFAULT_RULES_PATH));
    }

    #[test]
    fn present_keys_win() {
        let config: Config = toml::from_str(r#"rules_path = "/tmp/rules""#).unwrap();
        assert_eq!(config.rules_path, PathBuf::from("/tmp/rules"));
    }
}
