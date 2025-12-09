use std::{collections::HashMap, fs, path::Path, str::FromStr, sync::Arc};

use glob::glob;
use pulsar_core::{
    event::{PayloadDiscriminant, Value},
    pdk::{Event, ModuleContext},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use validatron::{Rule, ValidatronError};

use crate::{dsl, ruleset::Ruleset};

const RULE_EXTENSION: &str = "yaml";

#[derive(Debug, Deserialize)]
pub struct UserRule {
    name: String,
    r#type: String,
    condition: String,
    category: Category,
    severity: Severity,
    description: String,
}

/// Describes Pulsar Engine error.
#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug)]
pub enum RuleEngineError {
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
    #[error("Payload type '{0}' not found")]
    PayloadTypeNotFound(String),
}

#[derive(Clone)]
pub struct RuleEngine {
    internal: Arc<RuleEngineInternal>,
}

impl RuleEngine {
    pub fn new(rules_path: &Path, sender: ModuleContext) -> Result<Self, RuleEngineError> {
        let raw_rules = load_user_rules_from_dir(rules_path)?;

        let rules = parse_rules(raw_rules)?;

        let mut rulesets = HashMap::new();

        for (discriminant, rules) in rules {
            let ruleset = Ruleset::from_rules(rules)
                .map_err(|error| RuleEngineError::RuleCompile { error })?;

            if rulesets.insert(discriminant, ruleset).is_some() {
                unreachable!("hashmap rules -> ruleset is a 1:1 map")
            };
        }

        Ok(RuleEngine {
            internal: Arc::new(RuleEngineInternal { rulesets, sender }),
        })
    }

    pub fn process(&self, event: &Event) {
        // Run the engine only on non threat events to avoid creating loops
        if event.header().threat.is_none() {
            // Get payload discriminant from current event
            let discriminant = PayloadDiscriminant::from(event.payload());

            // Match against a discriminant ruleset if there is one
            if let Some(ruleset) = self.internal.rulesets.get(&discriminant) {
                for r in ruleset.matches(event) {
                    let metadata_value =
                        Value::try_from(&r.metadata).expect("failed to serialize metadata");
                    self.internal.sender.send_threat_derived(
                        event,
                        r.rule.name.clone(),
                        Some(metadata_value),
                    );
                }
            }
        }
    }
}

fn load_user_rules_from_dir(rules_path: &Path) -> Result<Vec<UserRule>, RuleEngineError> {
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
                RuleEngineError::RuleParsing {
                    filename: rule_file.path,
                    error,
                }
            })
        })
        .collect::<Result<Vec<Vec<UserRule>>, RuleEngineError>>()?;

    Ok(rules.into_iter().flatten().collect())
}

fn parse_rules(
    user_rules: Vec<UserRule>,
) -> Result<HashMap<PayloadDiscriminant, Vec<RuleWithMetadata>>, RuleEngineError> {
    let parser = dsl::dsl::ConditionParser::new();

    let rules = user_rules
        .into_iter()
        .map(|user_rule| parse_rule(&parser, user_rule))
        .collect::<Result<Vec<(PayloadDiscriminant, RuleWithMetadata)>, RuleEngineError>>()?;

    let mut m = HashMap::new();
    for (k, v) in rules {
        m.entry(k).or_insert_with(Vec::new).push(v)
    }

    Ok(m)
}

fn parse_rule(
    parser: &dsl::dsl::ConditionParser,
    user_rule: UserRule,
) -> Result<(PayloadDiscriminant, RuleWithMetadata), RuleEngineError> {
    let payload_discriminant = PayloadDiscriminant::from_str(&user_rule.r#type)
        .map_err(|_| RuleEngineError::PayloadTypeNotFound(user_rule.r#type.clone()))?;

    let condition = parser
        .parse(&user_rule.r#type, &user_rule.condition)
        .map_err(|err| RuleEngineError::DslError(user_rule.condition.clone(), err.to_string()))?;

    Ok((
        payload_discriminant,
        RuleWithMetadata {
            rule: Rule {
                name: user_rule.name,
                condition,
            },
            metadata: Metadata {
                category: user_rule.category,
                description: user_rule.description,
                severity: user_rule.severity,
                condition: user_rule.condition,
            },
        },
    ))
}

struct RuleEngineInternal {
    rulesets: HashMap<PayloadDiscriminant, Ruleset<Event>>,
    sender: ModuleContext,
}

#[derive(Debug, Clone)]
struct RuleFile {
    path: String,
    body: String,
}

impl RuleFile {
    pub fn from(path: &Path) -> Result<Self, RuleEngineError> {
        log::debug!("loading rule {}", path.display());
        let body = fs::read_to_string(path).map_err(|error| RuleEngineError::RuleLoading {
            name: path.display().to_string(),
            error,
        })?;
        let path = path.display().to_string();
        Ok(Self { path, body })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    pub category: Category,
    pub description: String,
    pub severity: Severity,
    pub condition: String,
}
/// An enriched rule with description and other fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleWithMetadata {
    pub(crate) rule: Rule,
    pub(crate) metadata: Metadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    CommandAndControl,
    CredentialAccess,
    DefenseEvasion,
    Discovery,
    Execution,
    Exfiltration,
    Generic,
    Impact,
    InitialAccess,
    LateralMovement,
    Persistence,
    PrivilegeEscalation,
    Reconnaissance,
    ResourceDevelopment,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[cfg(test)]
mod tests {
    use pulsar_core::event::PayloadDiscriminant;
    use validatron::{
        AdtField, Condition, Field, Identifier, Operator, RValue, RelationalOperator, Rule,
        SimpleField,
    };

    use crate::{
        dsl,
        engine::{Category, Metadata, RuleWithMetadata, Severity, UserRule, parse_rule},
    };

    #[test]
    fn test_rule_parse() {
        let parser = dsl::dsl::ConditionParser::new();

        let user_rule = UserRule {
            name: "Open netcat".to_string(),
            r#type: "Exec".to_string(),
            condition: r#"payload.filename == "/usr/bin/nc""#.to_string(),
            category: Category::Generic,
            description: "A rule to detect the use of netcat".to_string(),
            severity: Severity::Medium,
        };

        let parsed = parse_rule(&parser, user_rule).unwrap();

        let expected = (
            PayloadDiscriminant::Exec,
            RuleWithMetadata {
                rule: Rule {
                    name: "Open netcat".to_string(),
                    condition: Condition::Binary {
                        l: vec![
                            Identifier::Field(Field::Simple(SimpleField("payload".to_string()))),
                            Identifier::Field(Field::Adt(AdtField {
                                variant_name: "Exec".to_string(),
                                field_name: "filename".to_string(),
                            })),
                        ],
                        op: Operator::Relational(RelationalOperator::Equals),
                        r: RValue::Value("/usr/bin/nc".to_string()),
                    },
                },
                metadata: Metadata {
                    category: Category::Generic,
                    description: "A rule to detect the use of netcat".to_string(),
                    severity: Severity::Medium,
                    condition: r#"payload.filename == "/usr/bin/nc""#.to_string(),
                },
            },
        );

        assert_eq!(parsed, expected);
    }
}
