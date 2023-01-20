#![allow(clippy::type_complexity)]
use serde::{Deserialize, Serialize};

mod compiler;
mod engine;
mod error;
mod operators;
mod parser;
mod trait_impl;

pub use compiler::{compile_condition, validate_condition, ValidatedCondition};
pub use engine::Engine;
pub use error::ValidatronError;
pub use operators::*;

pub use parser::{Condition, Field, Rule};

pub use validatron_derive::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct UserRule {
    name: String,
    r#type: String,
    condition: String,
}

pub trait ValidatronStruct: Sized {
    fn validate_field(
        field_compare: &Field,
        op: Operator,
        value: &str,
    ) -> Result<Box<dyn Fn(&Self) -> bool + Send + Sync>, crate::ValidatronError>;
}

pub trait ValidatronVariant: Sized {
    fn validate(
        variant: &str,
        field_compare: &Field,
        op: Operator,
        value: &str,
    ) -> Result<(usize, Box<dyn Fn(&Self) -> bool + Send + Sync>), crate::ValidatronError>;

    fn var_num(&self) -> usize;
    fn var_num_of(variant: &str) -> Result<usize, crate::ValidatronError>;
}

pub trait ValidatronTypeProvider: Sized {
    fn field_type() -> ValidatronType<Self>;
}

pub struct Primitive<T: 'static> {
    pub parse_fn: Box<dyn Fn(&str) -> Result<T, ValidatronError>>,
    pub handle_op_fn: Box<
        dyn Fn(
            Operator,
        )
            -> Result<Box<dyn Fn(&T, &T) -> bool + Send + Sync + 'static>, ValidatronError>,
    >,
}

impl<T: Send + Sync + 'static> Primitive<T> {
    fn apply<F, S>(
        &self,
        extractor: F,
        op: Operator,
        value: &str,
    ) -> Result<Box<dyn Fn(&S) -> bool + Send + Sync + 'static>, ValidatronError>
    where
        F: Fn(&S) -> Option<&T> + Send + Sync + 'static,
    {
        let other = (self.parse_fn)(value)?;

        let compare_fn = (self.handle_op_fn)(op)?;

        Ok(Box::new(move |source: &S| {
            if let Some(field_content) = extractor(source) {
                return compare_fn(field_content, &other);
            }

            false
        }))
    }
}

pub enum ValidatronType<T: 'static> {
    Primitive(Primitive<T>),
    Struct(
        Box<
            dyn Fn(
                &Field,
                Operator,
                &str,
            ) -> Result<Box<dyn Fn(&T) -> bool + Send + Sync>, ValidatronError>,
        >,
    ),
    Collection(
        Box<
            dyn Fn(
                &Field,
                Operator,
                &str,
            ) -> Result<compiler::ValidatedCondition<T>, ValidatronError>,
        >,
    ),
}

pub fn process_struct<F, T, S>(
    field_compare: &Field,
    field_access_fn: F,

    op: Operator,
    value: &str,
) -> Result<Box<dyn Fn(&S) -> bool + Send + Sync>, ValidatronError>
where
    F: Fn(&S) -> &T + 'static + Send + Sync,
    T: ValidatronStruct + 'static,
{
    let validated_field_fn = T::validate_field(field_compare, op, value)?;

    Ok(Box::new(move |s| {
        let t = field_access_fn(s);
        validated_field_fn(t)
    }))
}

pub fn process_variant<F, T, S>(
    variant: &str,
    field_compare: &Field,
    field_access_fn: F,
    op: Operator,
    value: &str,
) -> Result<(usize, Box<dyn Fn(&S) -> bool + Send + Sync>), ValidatronError>
where
    F: Fn(&S) -> &T + 'static + Send + Sync,
    T: ValidatronVariant + 'static,
{
    let (var_num, validated_field_fn) = T::validate(variant, field_compare, op, value)?;

    Ok((
        var_num,
        Box::new(move |s| {
            let t = field_access_fn(s);
            validated_field_fn(t)
        }),
    ))
}

pub fn process_field<F, T, S>(
    field_name: &str,
    field_compare: &Field,
    field_access_fn: F,
    op: Operator,
    value: &str,
) -> Option<Result<Box<dyn Fn(&S) -> bool + Send + Sync>, ValidatronError>>
where
    F: Fn(&S) -> Option<&T> + 'static + Send + Sync,
    T: ValidatronTypeProvider + 'static + Send + Sync,
{
    match <T as crate::ValidatronTypeProvider>::field_type() {
        crate::ValidatronType::Primitive(p) => match field_compare {
            Field::Simple(field_compare_name) => {
                if field_compare_name != field_name {
                    return None;
                }

                let result = p.apply(field_access_fn, op, value);

                Some(result)
            }

            Field::Struct { name, .. } => {
                if name != field_name {
                    return None;
                }
                Some(Err(ValidatronError::FieldNotStruct(field_name.to_string())))
            }
        },
        crate::ValidatronType::Struct(validate_fn) => match field_compare {
            Field::Simple(field_compare_name) => {
                if field_compare_name != field_name {
                    return None;
                }
                Some(Err(ValidatronError::FieldNotSimple(field_name.to_string())))
            }
            Field::Struct { name, inner_field } => {
                if name != field_name {
                    return None;
                }
                let validated_field_fn = match validate_fn(inner_field, op, value) {
                    Ok(vcond) => vcond,
                    Err(err) => return Some(Err(err)),
                };

                Some(Ok(Box::new(move |s| {
                    field_access_fn(s)
                        .map(|f| validated_field_fn(f))
                        .unwrap_or(false)
                })))
            }
        },
        crate::ValidatronType::Collection(..) => match field_compare {
            Field::Simple(_) => {
                // TODO:
                todo!()
            }
            Field::Struct { .. } => {
                // TODO:
                todo!()
            }
        },
    }
}
