use serde::{Deserialize, Serialize};

mod builtins;
mod compiler;
mod error;
mod operators;
mod reflection;
mod ruleset;

pub mod validator;

pub use compiler::*;
pub use error::ValidatronError;
pub use operators::*;
pub use reflection::*;
pub use ruleset::*;

pub use validatron_derive::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    pub name: String,
    pub condition: Condition,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "content")]
pub enum Condition {
    And {
        l: Box<Condition>,
        r: Box<Condition>,
    },
    Or {
        l: Box<Condition>,
        r: Box<Condition>,
    },
    Not {
        inner: Box<Condition>,
    },
    Base {
        field_path: Vec<Field>,
        op: Operator,
        value: Match,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Field {
    Simple {
        field_name: String,
    },
    Adt {
        variant_name: String,
        field_name: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Match {
    Value(String),
    Field(Vec<Field>),
}
