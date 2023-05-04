use crate::{
    MultiOperator, Operator, RelationalOperator, Validatron, ValidatronClass, ValidatronError,
};

use std::{net::IpAddr, str::FromStr};

macro_rules! impl_numeric {
    ( $( $x:ty ),* ) => {
            $(
                impl $crate::Validatron for $x {
                    fn get_class() -> ValidatronClass {
                        Self::class_builder().primitive(
                            Box::new(|s| {
                                <$x>::from_str(s).map_err(|_| ValidatronError::FieldValueParseError(s.to_string()))
                            }),
                            Box::new(|op| match op {
                                Operator::Relational(op) => Ok(Box::new(move |a, b| op.apply(a, b))),
                                _ => Err(ValidatronError::OperatorNotAllowedOnType(
                                    op,
                                    stringify!($x).to_string(),
                                )),
                            }),
                        )
                    }
                }
            )*
    };

}

impl_numeric![i8, i16, i32, i64, i128, isize];
impl_numeric![u8, u16, u32, u64, u128, usize];
impl_numeric![f32, f64];

impl Validatron for String {
    fn get_class() -> ValidatronClass {
        Self::class_builder().primitive(
            Box::new(|s| {
                String::from_str(s)
                    .map_err(|_| ValidatronError::FieldValueParseError(s.to_string()))
            }),
            Box::new(|op| match op {
                Operator::String(op) => Ok(Box::new(move |a, b| op.apply(a, b))),
                Operator::Relational(op) => Ok(Box::new(move |a, b| op.apply(a, b))),
                Operator::Multi(op) => match op {
                    MultiOperator::Contains => Ok(Box::new(move |a, b| a.contains(b))),
                },
            }),
        )
    }
}

impl Validatron for bool {
    fn get_class() -> ValidatronClass {
        Self::class_builder().primitive(
            Box::new(|s| {
                bool::from_str(s).map_err(|_| ValidatronError::FieldValueParseError(s.to_string()))
            }),
            Box::new(|op| match &op {
                Operator::Relational(rel_op) => match rel_op {
                    RelationalOperator::Equals => Ok(Box::new(move |a, b| a == b)),
                    RelationalOperator::NotEquals => Ok(Box::new(move |a, b| a != b)),
                    _ => Err(ValidatronError::OperatorNotAllowedOnType(
                        op,
                        "bool".to_string(),
                    )),
                },
                _ => Err(ValidatronError::OperatorNotAllowedOnType(
                    op,
                    "bool".to_string(),
                )),
            }),
        )
    }
}

impl<T: Validatron + Send + Sync + 'static> Validatron for Vec<T> {
    fn get_class() -> ValidatronClass {
        Self::class_builder().collection::<T>()
    }
}

impl Validatron for IpAddr {
    fn get_class() -> ValidatronClass {
        Self::class_builder().primitive(
            Box::new(move |s| {
                IpAddr::from_str(s)
                    .map_err(|_| ValidatronError::FieldValueParseError(s.to_string()))
            }),
            Box::new(|op| match op {
                Operator::Relational(op) => Ok(Box::new(move |a, b| op.apply(a, b))),
                _ => Err(ValidatronError::OperatorNotAllowedOnType(
                    op,
                    "IpAddr".to_string(),
                )),
            }),
        )
    }
}
