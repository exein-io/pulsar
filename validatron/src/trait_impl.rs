use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use crate::*;

macro_rules! impl_numeric {
    ( $( $x:ty ),* ) => {
            $(
                impl $crate::ValidatronTypeProvider for $x {
                    fn field_type() -> $crate::ValidatronType<Self> {
                        $crate::ValidatronType::Primitive($crate::Primitive {
                            parse_fn: Box::new(move |s| {
                                <$x>::from_str(s).map_err(|_|$crate::ValidatronError::FieldValueParseError(s.to_string()))
                            }),
                            handle_op_fn: Box::new(|op| match op {
                                $crate::Operator::Relational(op) => Ok(Box::new(move |a, b| op.apply(a, b))),

                                _ => Err($crate::ValidatronError::OperatorNotAllowedOnType(
                                    op,
                                    stringify!($x).to_string(),
                                )),
                            }),
                        })
                    }
                }
            )*
    };

}

impl_numeric![i8, i16, i32, i64, i128, isize];
impl_numeric![u8, u16, u32, u64, u128, usize];
impl_numeric![f32, f64];

impl ValidatronTypeProvider for SocketAddr {
    fn field_type() -> ValidatronType<Self> {
        ValidatronType::Primitive(Primitive {
            parse_fn: Box::new(move |s| {
                SocketAddr::from_str(s)
                    .map_err(|_| ValidatronError::FieldValueParseError(s.to_string()))
            }),
            handle_op_fn: Box::new(|op| match op {
                Operator::Relational(op) => Ok(Box::new(move |a, b| op.apply(a, b))),
                _ => Err(ValidatronError::OperatorNotAllowedOnType(
                    op,
                    "SocketAddr".to_string(),
                )),
            }),
        })
    }
}

impl ValidatronTypeProvider for IpAddr {
    fn field_type() -> ValidatronType<Self> {
        ValidatronType::Primitive(Primitive {
            parse_fn: Box::new(move |s| {
                IpAddr::from_str(s)
                    .map_err(|_| ValidatronError::FieldValueParseError(s.to_string()))
            }),
            handle_op_fn: Box::new(|op| match op {
                Operator::Relational(op) => Ok(Box::new(move |a, b| op.apply(a, b))),
                _ => Err(ValidatronError::OperatorNotAllowedOnType(
                    op,
                    "IpAddr".to_string(),
                )),
            }),
        })
    }
}

impl ValidatronTypeProvider for String {
    fn field_type() -> ValidatronType<Self> {
        ValidatronType::Primitive(Primitive {
            parse_fn: Box::new(move |s| {
                String::from_str(s)
                    .map_err(|_| ValidatronError::FieldValueParseError(s.to_string()))
            }),
            handle_op_fn: Box::new(|op| match op {
                Operator::String(op) => Ok(Box::new(move |a, b| op.apply(a, b))),
                Operator::Relational(op) => Ok(Box::new(move |a, b| op.apply(a, b))),
                _ => Err(ValidatronError::OperatorNotAllowedOnType(
                    op,
                    "String".to_string(),
                )),
            }),
        })
    }
}

impl ValidatronTypeProvider for bool {
    fn field_type() -> ValidatronType<Self> {
        ValidatronType::Primitive(Primitive {
            parse_fn: Box::new(move |s| {
                bool::from_str(s).map_err(|_| ValidatronError::FieldValueParseError(s.to_string()))
            }),
            handle_op_fn: Box::new(|op| match op {
                Operator::Relational(op) => Ok(Box::new(move |a, b| op.apply(a, b))),
                _ => Err(ValidatronError::OperatorNotAllowedOnType(
                    op,
                    "bool".to_string(),
                )),
            }),
        })
    }
}

impl<T: ValidatronTypeProvider> ValidatronTypeProvider for Vec<T> {
    fn field_type() -> ValidatronType<Self> {
        ValidatronType::Collection(Box::new(move |_, _, _| {
            // TODO:
            todo!()
        }))
    }
}
