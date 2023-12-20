//! validatron is a library for check the correctness of rules over types and subsequent compilation into a single function.
//!
//! It check if fields specified in a rules are valid for a given type. Example:
//!
//! ```
//! use validatron::{validator::get_valid_rule, Validatron, Field, Identifier, RValue, RelationalOperator, Operator};
//!
//! #[derive(Validatron)]
//! struct MyStruct {
//!     my_value: i32
//! }
//!
//! let rule = get_valid_rule::<MyStruct>(
//!     vec![Identifier::Field(Field::Simple {
//!         field_name: "my_value".to_string(),
//!     })],
//!     Operator::Relational(RelationalOperator::Equals),
//!     RValue::Value("42".to_string()),
//! )
//! .unwrap();
//!
//! let test = MyStruct { my_value: 42 };
//!
//! assert!(rule.is_match(&test))
//! ```
//!
//! It will check if the field `my_value` exists in the `MyStruct` type and if it's possible to parse the input string `"42"` into the
//! specific field type [i32].
//!
//! On top of this it's possible to write complex rules, assembling conditions with logical operators (AND, OR, NOT). Example:
//!
//! ```
//! use validatron::{Ruleset, Rule, Validatron, Operator, RelationalOperator, Condition, Identifier, RValue, Field};
//!
//! #[derive(Validatron)]
//! struct MyStruct {
//!     my_value: i32,
//! }
//!
//! let ruleset: Ruleset<MyStruct> = Ruleset::from_rules(vec![
//!     Rule {
//!         name: "my_value equal to 3 or 5".to_string(),
//!         condition: Condition::Or {
//!             l: Box::new(Condition::Binary {
//!                 l: vec![Identifier::Field(Field::Simple {
//!                     field_name: "my_value".to_string(),
//!                 })],
//!                 op: Operator::Relational(RelationalOperator::Equals),
//!                 r: RValue::Value("3".to_string()),
//!             }),
//!             r: Box::new(Condition::Binary {
//!                 l: vec![Identifier::Field(Field::Simple {
//!                     field_name: "my_value".to_string(),
//!                 })],
//!                 op: Operator::Relational(RelationalOperator::Equals),
//!                 r: RValue::Value("5".to_string()),
//!             }),
//!         },
//!     },
//!     Rule {
//!         name: "my_value greater than 100".to_string(),
//!         condition: Condition::Binary {
//!             l: vec![Identifier::Field(Field::Simple {
//!                 field_name: "my_value".to_string(),
//!             })],
//!             op: Operator::Relational(RelationalOperator::Greater),
//!             r: RValue::Value("100".to_string()),
//!         },
//!     },
//! ])
//! .unwrap();
//!
//! let test = MyStruct {
//!     my_value: 42
//! };
//!
//! for rule in ruleset.matches(&test) {
//!     println!("Matched rule {}", rule.name)
//! }
//! ```
//!
//! Check the [ruleset] module for more details.
//!
//! To better understand the underlying implementation, take a look at the [reflection] module.

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

/// Representation of a simple rule.
///
/// It consists of a name and a [Condition] AST.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    pub name: String,
    pub condition: Condition,
}

impl Rule {
    pub fn compile<T: Validatron>(self) -> Result<CompiledRule<T>, ValidatronError> {
        self.condition
            .validate()
            .map(|validated_condition| CompiledRule {
                name: self.name,
                condition: validated_condition.compile(),
            })
    }
}

/// Representation of conditions used as input to [validator::get_valid_rule] before validation.
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
    Binary {
        l: Vec<Identifier>,
        op: Operator,
        r: RValue,
    },
    Unary(Vec<Identifier>),
}

/// Respresents the path of field in a structure, with the possibility of an ending method call
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "content")]
pub enum Identifier {
    Field(Field),
    MethodCall(MethodCall),
}

/// Represents the path of a field into a structure ([Field::Simple]) or into an enum ([Field::Adt])
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "content")]
pub enum Field {
    /// struct field
    Simple { field_name: String },
    /// enum field
    Adt {
        variant_name: String,
        field_name: String,
    },
}

/// Respresents a method call on an identifier
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MethodCall {
    name: String,
}

/// Argument of the operator. It can be a simple [String] or it can be another field represented as
/// fieldpath ([Vec<Field>]) on a type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "content")]
pub enum RValue {
    Value(String),
    Identifier(Vec<Identifier>),
}
