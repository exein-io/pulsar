use std::{fs, path::Path, sync::Arc};

use glob::glob;
use pulsar_core::{
    event::Value,
    pdk::{Event, ModuleSender},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use validatron::{Rule, Ruleset, ValidatronError};

use crate::dsl;

const RULE_EXTENSION: &str = "yaml";

#[derive(Debug, Serialize, Deserialize)]
pub struct UserRule {
    name: String,
    r#type: String,
    condition: String,
}

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
    #[error("Error validating dsl '{0}': {1}")]
    DslError(String, String),
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
        let raw_rules = load_user_rules_from_dir(rules_path)?;

        let rules = parse_rules(raw_rules)?;

        let ruleset =
            Ruleset::from_rules(rules).map_err(|error| PulsarEngineError::RuleCompile { error })?;

        Ok(PulsarEngine {
            internal: Arc::new(PulsarEngineInternal { ruleset, sender }),
        })
    }

    pub fn process(&self, event: &Event) {
        // Run the engine only on non threat events to avoid creating loops
        if event.header().threat.is_none() {
            self.internal.ruleset.run(event, |rule| {
                emit_event(&self.internal.sender, event, &rule.name)
            })
        }
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

fn parse_rules(user_rules: Vec<UserRule>) -> Result<Vec<Rule>, PulsarEngineError> {
    let parser = dsl::dsl::ConditionParser::new();

    let rules = user_rules
        .into_iter()
        .map(|user_rule| parse_rule(&parser, user_rule))
        .collect::<Result<Vec<Rule>, PulsarEngineError>>()?;

    Ok(rules)
}

fn parse_rule(
    parser: &dsl::dsl::ConditionParser,
    user_rule: UserRule,
) -> Result<Rule, PulsarEngineError> {
    let condition = parser
        .parse(&user_rule.r#type, &user_rule.condition)
        .map_err(|err| PulsarEngineError::DslError(user_rule.condition.clone(), err.to_string()))?;

    Ok(Rule {
        name: user_rule.name,
        condition,
    })
}

fn emit_event(sender: &ModuleSender, old_event: &Event, rule_name: &str) {
    let data = RuleEngineData {
        rule_name: rule_name.to_string(),
    };

    let data = Value::try_from(data).unwrap();

    sender.send_threat_derived(old_event, data)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuleEngineData {
    pub rule_name: String,
}

struct PulsarEngineInternal {
    ruleset: Ruleset<Event>,
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

#[cfg(test)]
mod tests {
    use validatron::{Condition, Field, Match, Operator, RelationalOperator, Rule};

    use crate::{
        dsl,
        engine::{parse_rule, UserRule},
    };

    #[test]
    fn test_rule_parse() {
        let parser = dsl::dsl::ConditionParser::new();

        let user_rule = UserRule {
            name: "Open netcat".to_string(),
            r#type: "Exec".to_string(),
            condition: r#"payload.filename == "/usr/bin/nc""#.to_string(),
        };

        let parsed = parse_rule(&parser, user_rule).unwrap();

        let expected = Rule {
            name: "Open netcat".to_string(),
            condition: Condition::Base {
                field_path: vec![
                    Field::Simple {
                        field_name: "payload".to_string(),
                    },
                    Field::Adt {
                        variant_name: "Exec".to_string(),
                        field_name: "filename".to_string(),
                    },
                ],
                op: Operator::Relational(RelationalOperator::Equals),
                value: Match::Value("/usr/bin/nc".to_string()),
            },
        };

        assert_eq!(parsed, expected);
    }
}
