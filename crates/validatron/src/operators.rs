//! This module contains operators available on [super::Primitive] types.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ValidatronError;

/// An operator closure take two &T and returns whether the supplied arguments
/// satisfy the Operator this closure implements.
pub type OperatorFn<T> = Box<dyn Fn(&T, &T) -> bool + Send + Sync + 'static>;

// The OperatorFactory of T, given an abstract operation, returns the concrete
// closure which implements that specific check.
pub type HandleOperatorFn<T> =
    Box<dyn Fn(Operator) -> Result<OperatorFn<T>, ValidatronError> + Send + Sync + 'static>;

/// Enum of all all possible operators.
/// These represent the abastract operators, for the concrete
/// implementstions of these, see OperatorFn<T>.
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

/// Operators intended to be used on strings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "content")]
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

/// Relational operators.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "content")]
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

/// Operators intended to be used on for collections.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "content")]
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
