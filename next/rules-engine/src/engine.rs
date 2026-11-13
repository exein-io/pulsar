use std::{collections::HashMap, fs, path::Path};

use glob::glob;
use next_core::{
    Schema,
    event::Event,
    payload::{KindOf, PayloadKind, PayloadSet},
    threat::{Category, Severity},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use validatron::{
    AdtField, Condition, Field, Identifier, RValue, Rule, Validatron, ValidatronClass,
    ValidatronClassKind, ValidatronError,
};

use crate::{dsl, ruleset::Ruleset};

const RULE_EXTENSION: &str = "toml";

/// Content of a rule file: an array of tables under a single `rules` key.
#[derive(Debug, Deserialize)]
struct RuleDocument {
    rules: Vec<UserRule>,
}

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
        error: toml::de::Error,
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

/// The compiled rules, by the payload kind they apply to.
pub struct RuleEngine<S: Schema> {
    rulesets: HashMap<KindOf<S>, Ruleset<Event<S::Payload>>>,
}

impl<S: Schema> RuleEngine<S> {
    pub fn new(rules_path: &Path) -> Result<Self, RuleEngineError> {
        let raw_rules = load_user_rules_from_dir(rules_path)?;

        let rules = parse_rules::<S>(raw_rules)?;

        let mut rulesets = HashMap::new();

        for (kind, rules) in rules {
            let ruleset = Ruleset::from_rules(rules)
                .map_err(|error| RuleEngineError::RuleCompile { error })?;

            if rulesets.insert(kind, ruleset).is_some() {
                unreachable!("hashmap rules -> ruleset is a 1:1 map")
            };
        }

        Ok(RuleEngine { rulesets })
    }

    /// The payload kinds some rule applies to.
    pub fn kinds(&self) -> Vec<KindOf<S>> {
        self.rulesets.keys().copied().collect()
    }

    /// The name and metadata of every rule `event` matches.
    pub fn matches<'a>(
        &'a self,
        event: &'a Event<S::Payload>,
    ) -> impl Iterator<Item = (&'a str, &'a Metadata)> {
        self.rulesets
            .get(&event.payload.kind())
            .into_iter()
            .flat_map(move |ruleset| ruleset.matches(event))
            .map(|rule| (rule.rule.name.as_str(), &rule.metadata))
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
            toml::from_str::<RuleDocument>(&rule_file.body)
                .map(|document| document.rules)
                .map_err(|error| RuleEngineError::RuleParsing {
                    filename: rule_file.path,
                    error,
                })
        })
        .collect::<Result<Vec<Vec<UserRule>>, RuleEngineError>>()?;

    Ok(rules.into_iter().flatten().collect())
}

fn parse_rules<S: Schema>(
    user_rules: Vec<UserRule>,
) -> Result<HashMap<KindOf<S>, Vec<RuleWithMetadata>>, RuleEngineError> {
    let parser = dsl::dsl::ConditionParser::new();

    let rules = user_rules
        .into_iter()
        .map(|user_rule| parse_rule::<S>(&parser, user_rule))
        .collect::<Result<Vec<(KindOf<S>, RuleWithMetadata)>, RuleEngineError>>()?;

    let mut m = HashMap::new();
    for (k, v) in rules {
        m.entry(k).or_insert_with(Vec::new).push(v)
    }

    Ok(m)
}

fn parse_rule<S: Schema>(
    parser: &dsl::dsl::ConditionParser,
    user_rule: UserRule,
) -> Result<(KindOf<S>, RuleWithMetadata), RuleEngineError> {
    let kind = KindOf::<S>::from_name(&user_rule.r#type)
        .ok_or_else(|| RuleEngineError::PayloadTypeNotFound(user_rule.r#type.clone()))?;

    let condition = parser
        .parse(&user_rule.r#type, &user_rule.condition)
        .map_err(|err| RuleEngineError::DslError(user_rule.condition.clone(), err.to_string()))?;
    let condition = with_some_steps::<Event<S::Payload>>(condition);

    Ok((
        kind,
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

/// Inserts the `Some` step wherever a rule's path goes through an `Option`,
/// so `header.image == "/bin/sh"` reads the image when it is known. A path
/// to an unknown value doesn't match, so its condition is false and a NOT
/// of it is true. Methods of `Option` itself (`is_some()`) are kept as they
/// are.
fn with_some_steps<T: Validatron>(condition: Condition) -> Condition {
    match condition {
        Condition::And { l, r } => Condition::And {
            l: Box::new(with_some_steps::<T>(*l)),
            r: Box::new(with_some_steps::<T>(*r)),
        },
        Condition::Or { l, r } => Condition::Or {
            l: Box::new(with_some_steps::<T>(*l)),
            r: Box::new(with_some_steps::<T>(*r)),
        },
        Condition::Not { inner } => Condition::Not {
            inner: Box::new(with_some_steps::<T>(*inner)),
        },
        Condition::Binary { l, op, r } => Condition::Binary {
            l: path_with_some_steps(l, T::get_class()),
            op,
            r: match r {
                RValue::Identifier(path) => {
                    RValue::Identifier(path_with_some_steps(path, T::get_class()))
                }
                value => value,
            },
        },
        Condition::Unary(path) => Condition::Unary(path_with_some_steps(path, T::get_class())),
    }
}

fn path_with_some_steps(path: Vec<Identifier>, root: ValidatronClass) -> Vec<Identifier> {
    let some = || {
        Identifier::Field(Field::Adt(AdtField {
            variant_name: "Some".to_string(),
            field_name: "0".to_string(),
        }))
    };
    let mut steps = Vec::with_capacity(path.len() + 1);
    // The class reached so far. `None` once the path leaves what reflection
    // describes; the rest of the path is then kept as written.
    let mut class = Some(root);
    for step in path {
        while let Some(current) = class.as_ref().filter(|class| is_option(class)) {
            if let Identifier::MethodCall(call) = &step
                && current.get_method(&call.name).is_some()
            {
                break;
            }
            let next = inner(current, "Some", "0");
            steps.push(some());
            class = next;
        }
        class = class.and_then(|current| match &step {
            Identifier::Field(Field::Simple(field)) => match current.kind() {
                ValidatronClassKind::Struct(s) => s.get_field(&field.0).map(|f| f.get_class()),
                _ => None,
            },
            Identifier::Field(Field::Adt(field)) => {
                inner(&current, &field.variant_name, &field.field_name)
            }
            Identifier::MethodCall(call) => current.get_method(&call.name).map(|m| m.get_class()),
        });
        steps.push(step);
    }
    while let Some(current) = class.as_ref().filter(|class| is_option(class)) {
        let next = inner(current, "Some", "0");
        steps.push(some());
        class = next;
    }
    steps
}

fn is_option(class: &ValidatronClass) -> bool {
    class.get_name().starts_with("core::option::Option<")
}

fn inner(class: &ValidatronClass, variant: &str, field: &str) -> Option<ValidatronClass> {
    match class.kind() {
        ValidatronClassKind::Enum(e) => e.get_variant_field(variant, field).map(|f| f.get_class()),
        _ => None,
    }
}
