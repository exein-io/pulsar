//! The rules engine as a detector: TOML rules over any [`Schema`]'s events,
//! extension kinds included.

use std::{path::PathBuf, sync::Arc};

use engine::RuleEngine;
use next_core::{
    Schema,
    event::Event,
    payload::KindOf,
    processor::{DetectCtx, Detector, Interest},
    threat::RuleThreat,
};
use serde::Deserialize;

mod dsl;
mod engine;
mod ruleset;

pub use engine::{Metadata, RuleEngineError};

const DEFAULT_RULES_PATH: &str = "/etc/pulsar/rules";

pub struct RulesDetector<S: Schema> {
    engine: RuleEngine<S>,
}

impl<S: Schema> RulesDetector<S> {
    pub fn new(config: &Config) -> Result<Self, RuleEngineError> {
        Ok(Self {
            engine: RuleEngine::new(&config.rules_path)?,
        })
    }
}

impl<S: Schema> Detector<S> for RulesDetector<S> {
    fn name(&self) -> &'static str {
        "rules-engine"
    }

    fn interest(&self) -> Interest<KindOf<S>> {
        Interest::Kinds(self.engine.kinds())
    }

    fn on_event(&mut self, event: &Arc<Event<S::Payload>>, cx: &mut DetectCtx<'_, S>) {
        for (rule, metadata) in self.engine.matches(event) {
            cx.report(
                RuleThreat {
                    rule: rule.to_string(),
                    category: metadata.category.clone(),
                    severity: metadata.severity.clone(),
                },
                metadata.description.clone(),
            );
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Directory scanned recursively for rule files.
    pub rules_path: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rules_path: PathBuf::from(DEFAULT_RULES_PATH),
        }
    }
}
