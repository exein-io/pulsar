use std::{fs, path::Path, sync::Arc};

use glob::glob;
use pulsar_core::{
    pdk::{Event, ModuleSender, Payload},
    Pid, Timestamp,
};
use thiserror::Error;
use validatron::{Engine, UserRule, ValidatronError};

const RULE_EXTENSION: &str = "yaml";

/// Describes Pulsar Engine error.
#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug)]
pub enum PulsarEngineError {
    #[error("Error listing rules: {0}")]
    RuleListing(#[from] glob::PatternError),
    #[error("Error reading rule: {name}")]
    RuleLoading {
        name: String,
        #[source]
        error: std::io::Error,
    },
    #[error("Error parsing rule file: {filename}")]
    RuleParsing {
        filename: String,
        #[source]
        error: serde_yaml::Error,
    },
    #[error("Error compiling rules: {error}")]
    RuleCompile {
        #[source]
        error: ValidatronError,
    },
}

#[derive(Clone)]
pub struct PulsarEngine {
    internal: Arc<PulsarEngineInternal>,
}

impl PulsarEngine {
    pub fn new(rules_path: &Path, sender: ModuleSender) -> Result<Self, PulsarEngineError> {
        let rules = load_user_rules_from_dir(rules_path)?;

        let engine = Engine::from_user_rules(rules)
            .map_err(|error| PulsarEngineError::RuleCompile { error })?;

        Ok(PulsarEngine {
            internal: Arc::new(PulsarEngineInternal { engine, sender }),
        })
    }

    pub fn process(&self, event: &Event) {
        self.internal.engine.run(event, |rule| {
            emit_event(&self.internal.sender, event, &rule.name)
        })
    }
}

fn load_user_rules_from_dir(rules_path: &Path) -> Result<Vec<UserRule>, PulsarEngineError> {
    let mut rule_files = Vec::new();

    let expr = format!("{}/**/*.{}", rules_path.display(), RULE_EXTENSION);
    let entries = glob(&expr)?;
    for path in entries.flatten() {
        let rule_file = RuleFile::from(&path)?;
        rule_files.push(rule_file);
    }

    let rules = rule_files
        .into_iter()
        .map(|rule_file| {
            serde_yaml::from_str::<Vec<UserRule>>(&rule_file.body).map_err(|error| {
                PulsarEngineError::RuleParsing {
                    filename: rule_file.path,
                    error,
                }
            })
        })
        .collect::<Result<Vec<Vec<UserRule>>, PulsarEngineError>>()?;

    Ok(rules.into_iter().flatten().collect())
}

fn emit_event(sender: &ModuleSender, old_event: &Event, rule_name: &str) {
    let pid = Pid::from_raw(old_event.header.pid);

    let payload = Payload::RuleEngineDetection {
        rule_name: rule_name.to_string(),
        payload: Box::new(old_event.payload.clone()),
    };

    sender.send_threat(pid, Timestamp::now(), payload)
}

struct PulsarEngineInternal {
    engine: Engine<Event>,
    sender: ModuleSender,
}

#[derive(Debug, Clone)]
struct RuleFile {
    path: String,
    body: String,
}

impl RuleFile {
    pub fn from(path: &Path) -> Result<Self, PulsarEngineError> {
        log::debug!("loading rule {}", path.display());
        let body = fs::read_to_string(path).map_err(|error| PulsarEngineError::RuleLoading {
            name: path.display().to_string(),
            error,
        })?;
        let path = path.display().to_string();
        Ok(Self { path, body })
    }
}
