use std::fmt::Display;

use serde::{Deserialize, Serialize};

use crate::Operator;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub typ: String,
    pub condition: Condition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        field: Field,
        op: Operator,
        value: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "content")]
pub enum Field {
    Simple(String),
    Struct {
        name: String,
        inner_field: Box<Field>,
    },
}

impl Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Field::Simple(name) => write!(f, "{name}"),
            Field::Struct { name, inner_field } => write!(f, "{name}.{}", inner_field),
        }
    }
}
