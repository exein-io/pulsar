use std::{fmt::Display, str::FromStr};

use lalrpop_util::lalrpop_mod;
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

impl FromStr for Field {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let split_by_dot = s.split(".").collect::<Vec<&str>>();

        let mut reversed = split_by_dot.iter().rev();

        let first = reversed
            .next()
            .ok_or("Field should have a least one character except '.'")?;

        let root = Field::Simple(first.to_string());

        let composed = reversed.fold(root, |acc, curr| Field::Struct {
            name: curr.to_string(),
            inner_field: Box::new(acc),
        });

        Ok(composed)
    }
}

lalrpop_mod!(dsl); // syntesized by LALRPOP

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test1() {
        let p = dsl::ConditionParser::new().parse(r#"header.pid == "3""#);
        assert!(p.is_ok())
    }

    #[test]
    fn test2() {
        let p = dsl::ConditionParser::new().parse(r#"header == "3""#);
        assert!(p.is_ok())
    }

    #[test]
    fn test3() {
        let p = dsl::ConditionParser::new().parse(r#"header.image == "systemd""#);
        assert!(p.is_ok())
    }

    #[test]
    fn test4() {
        let p = dsl::ConditionParser::new().parse(r#"header.image starts_with "systemd""#);
        assert!(p.is_ok())
    }

    #[test]
    fn test5() {
        let p = dsl::ConditionParser::new().parse(r#"header.pid == "3""#);
        assert!(p.is_ok())
    }

    #[test]
    fn test6() {
        let p = dsl::ConditionParser::new().parse(r#"header.pid.inner == "3""#);
        assert!(p.is_ok())
    }
}
