use thiserror::Error;

use crate::Operator;

#[derive(Error, Debug)]
pub enum ValidatronError {
    #[error("Error validating dsl '{0}': {1}")]
    DslError(String, String),
    #[error("Variant not found: {0}")]
    ViariantNotFound(String),
    #[error("Field not found: {0}")]
    FieldNotFound(String),
    #[error("Field {0} not struct")]
    FieldNotStruct(String),
    #[error("Field {0} not simple")]
    FieldNotSimple(String),
    #[error("Error parsing value {0}")]
    FieldValueParseError(String),
    #[error("Operator {0} not allowed on type {1}")]
    OperatorNotAllowedOnType(Operator, String),
    #[error("Type not primitive, can't parse {0}")]
    TypeNotPrimitive(String),
    #[error("Collection field {0} is not primitive")]
    CollectionFieldNotPrimitive(String),
}
