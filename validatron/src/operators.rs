use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "content")]
pub enum Operator {
    Relational(RelationalOperator),
    String(StringOperator),
    Multi(MultiOperator),
}

impl fmt::Display for Operator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StringOperator {
    StartsWith,
    EndsWith,
    // Regex,
}

impl StringOperator {
    pub fn apply<T: AsRef<str>>(&self, first: T, second: T) -> bool {
        match self {
            StringOperator::StartsWith => first.as_ref().starts_with(second.as_ref()),
            StringOperator::EndsWith => first.as_ref().ends_with(second.as_ref()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelationalOperator {
    Equals,
    NotEquals,
    Greater,
    Less,
    GreaterEqual,
    LessEqual,
}

impl RelationalOperator {
    pub fn apply<T: PartialEq + PartialOrd>(&self, first: T, second: T) -> bool {
        match self {
            RelationalOperator::Equals => first == second,
            RelationalOperator::NotEquals => first != second,
            RelationalOperator::Greater => first > second,
            RelationalOperator::Less => first < second,
            RelationalOperator::GreaterEqual => first >= second,
            RelationalOperator::LessEqual => first >= second,
        }
    }
}

impl fmt::Display for RelationalOperator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MultiOperator {
    Contains,
}

impl fmt::Display for MultiOperator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MultiOperator::Contains => write!(f, "contains"),
        }
    }
}
