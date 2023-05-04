use thiserror::Error;

use crate::Operator;

#[derive(Debug, Error)]
pub enum ValidatronError {
    #[error("Error parsing value {0}")]
    FieldValueParseError(String),
    #[error("Operator {0} not allowed on type {1}")]
    OperatorNotAllowedOnType(Operator, String),
    #[error("Attribute not found: {0}")]
    AttributeNotFound(String),
    #[error("Variant Attribute not found: {0}+{1}")]
    VariantAttributeNotFound(String, String),
    #[error("Field type error, expecting type: {0}")]
    FieldTypeError(String),
    #[error("No more fields on the type: {0}")]
    NoMoreFieldsError(String),
    #[error("Comparing field not primitive")]
    ComparingFieldNotPrimitive,
    #[error("Comparing diffent field type")]
    DifferentFieldsType,
    #[error("Collection value not primitive")]
    CollectionValueNotPrimitive,
}
