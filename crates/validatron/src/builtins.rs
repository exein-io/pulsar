//! This module contains implementation for Rust primitive types and few types other types of the standard library

use crate::{
    MultiOperator, Operator, RelationalOperator, Validatron, ValidatronClass, ValidatronError,
};

use std::{net::IpAddr, str::FromStr};

macro_rules! impl_numeric {
    ( $( $x:ty ),* ) => {
            $(
                impl $crate::Validatron for $x {
                    fn get_class() -> ValidatronClass {
                        Self::class_builder().primitive_class_builder(
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
                        ).build()
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
        Self::class_builder()
            .primitive_class_builder(
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
            .build()
    }
}

impl Validatron for bool {
    fn get_class() -> ValidatronClass {
        Self::class_builder()
            .primitive_class_builder(
                Box::new(|s| {
                    bool::from_str(s)
                        .map_err(|_| ValidatronError::FieldValueParseError(s.to_string()))
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
            .build()
    }
}

impl<T: Validatron + Send + Sync + 'static> Validatron for Vec<T> {
    fn get_class() -> ValidatronClass {
        Self::class_builder().collection_clas_builder::<T>().build()
    }
}

impl Validatron for IpAddr {
    fn get_class() -> ValidatronClass {
        Self::class_builder()
            .primitive_class_builder(
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
            .build()
    }
}

impl<T: Validatron + Send + Sync + 'static> Validatron for Option<T> {
    fn get_class() -> ValidatronClass {
        Self::class_builder()
            .enum_class_builder()
            .add_variant_field("Some", "0", Box::new(Option::as_ref))
            .add_method0("is_some", Box::new(|c| c.is_some()))
            .build()
    }
}

#[cfg(test)]
mod test {
    use crate::{
        AdtField, Field, Identifier, MethodCall, Operator, RValue, RelationalOperator, SimpleField,
        Validatron,
        validator::{get_valid_rule, get_valid_unary_rule},
    };

    #[test]
    fn test_option_no_method() {
        let rule = get_valid_unary_rule::<Option<i32>>(vec![Identifier::MethodCall(MethodCall {
            name: "emos_si".to_string(),
        })]);

        assert!(rule.is_err());
    }

    #[test]
    fn test_option_positive() {
        let rule = get_valid_unary_rule::<Option<i32>>(vec![Identifier::MethodCall(MethodCall {
            name: "is_some".to_string(),
        })])
        .unwrap();

        let test = Some(666);

        assert!(rule.is_match(&test));
    }

    #[test]
    fn test_option_negative() {
        let rule = get_valid_unary_rule::<Option<i32>>(vec![Identifier::MethodCall(MethodCall {
            name: "is_some".to_string(),
        })])
        .unwrap();

        let test = None;

        assert!(!rule.is_match(&test));
    }

    #[test]
    fn test_option_field_success() {
        struct A {
            a: i32,
        }

        impl Validatron for A {
            fn get_class() -> crate::ValidatronClass {
                Self::class_builder()
                    .struct_class_builder()
                    .add_field("a", Box::new(|t| &t.a))
                    .build()
            }
        }

        let rule = get_valid_rule::<Option<A>>(
            vec![
                Identifier::Field(Field::Adt(AdtField {
                    variant_name: "Some".to_string(),
                    field_name: "0".to_string(),
                })),
                Identifier::Field(Field::Simple(SimpleField("a".to_string()))),
            ],
            Operator::Relational(RelationalOperator::Equals),
            RValue::Value("5".to_string()),
        )
        .unwrap();

        let test = Some(A { a: 5 });

        assert!(rule.is_match(&test));
    }

    #[test]
    fn test_option_field_fail() {
        struct A {
            a: i32,
        }

        impl Validatron for A {
            fn get_class() -> crate::ValidatronClass {
                Self::class_builder()
                    .struct_class_builder()
                    .add_field("a", Box::new(|t| &t.a))
                    .build()
            }
        }

        let rule = get_valid_rule::<Option<A>>(
            vec![
                Identifier::Field(Field::Adt(AdtField {
                    variant_name: "Some".to_string(),
                    field_name: "0".to_string(),
                })),
                Identifier::Field(Field::Simple(SimpleField("a".to_string()))),
            ],
            Operator::Relational(RelationalOperator::Equals),
            RValue::Value("5".to_string()),
        )
        .unwrap();

        let test = None;

        assert!(!rule.is_match(&test));
    }

    #[test]
    fn test_option_field_nested_success() {
        struct A {
            b: Option<B>,
        }

        struct B {
            c: C,
        }

        struct C {
            inner: i32,
        }

        impl Validatron for A {
            fn get_class() -> crate::ValidatronClass {
                Self::class_builder()
                    .struct_class_builder()
                    .add_field("b", Box::new(|t| &t.b))
                    .build()
            }
        }

        impl Validatron for B {
            fn get_class() -> crate::ValidatronClass {
                Self::class_builder()
                    .struct_class_builder()
                    .add_field("c", Box::new(|t| &t.c))
                    .build()
            }
        }

        impl Validatron for C {
            fn get_class() -> crate::ValidatronClass {
                Self::class_builder()
                    .struct_class_builder()
                    .add_field("inner", Box::new(|t| &t.inner))
                    .build()
            }
        }

        let rule = get_valid_rule::<A>(
            vec![
                Identifier::Field(Field::Simple(SimpleField("b".to_string()))),
                Identifier::Field(Field::Adt(AdtField {
                    variant_name: "Some".to_string(),
                    field_name: "0".to_string(),
                })),
                Identifier::Field(Field::Simple(SimpleField("c".to_string()))),
                Identifier::Field(Field::Simple(SimpleField("inner".to_string()))),
            ],
            Operator::Relational(RelationalOperator::Equals),
            RValue::Value("666".to_string()),
        )
        .unwrap();

        let test = A {
            b: Some(B {
                c: C { inner: 666 },
            }),
        };

        assert!(rule.is_match(&test));
    }
}
