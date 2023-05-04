use std::{any::Any, collections::VecDeque};

use crate::{
    Field, Match, MultiOperator, Operator, Validatron, ValidatronClass, ValidatronClassKind,
    ValidatronError,
};

pub struct ValidRule<T: Validatron> {
    pub(crate) rule_fn: Box<dyn Fn(&T) -> bool + Send + Sync>,
}

impl<T: Validatron + 'static> ValidRule<T> {
    pub fn is_match(&self, t: &T) -> bool {
        (self.rule_fn)(t)
    }
}

struct ValidField<T: Validatron> {
    class: ValidatronClass,
    extractor: ExtractorFrom<T>,
}

enum ExtractorFrom<T: Validatron> {
    Some(Box<dyn Fn(&T) -> Option<&dyn Any> + Send + Sync>),
    None,
}

impl<T: Validatron + 'static> ExtractorFrom<T> {
    fn to_extract_fn(self) -> Box<dyn Fn(&T) -> Option<&dyn Any> + Send + Sync> {
        match self {
            ExtractorFrom::Some(extract_fn) => extract_fn,
            ExtractorFrom::None => Box::new(|t| Some(t as &dyn Any)),
        }
    }
}

impl<T: Validatron + 'static> ExtractorFrom<T> {
    fn chain(self, next: Box<dyn Fn(&dyn Any) -> Option<&dyn Any> + Send + Sync>) -> Self {
        match self {
            ExtractorFrom::Some(current) => {
                ExtractorFrom::Some(Box::new(move |t| current(t).and_then(&next)))
            }
            ExtractorFrom::None => ExtractorFrom::Some(Box::new(move |t| next(t as &dyn Any))),
        }
    }
}

pub fn get_valid_rule<T: Validatron + 'static>(
    field_path: Vec<Field>,
    op: Operator,
    value: Match,
) -> Result<ValidRule<T>, ValidatronError> {
    let class = T::get_class();

    let first_field =
        get_valid_field_from_class::<T>(class, field_path.into(), ExtractorFrom::None)?;

    let vr = match first_field.class.into_kind() {
        ValidatronClassKind::Primitive(first_field_primitive) => match value {
            Match::Value(value) => {
                let compare_fn =
                    unsafe { first_field_primitive.compare_fn_any_value_unchecked(op, &value) }?;

                let extractor_fn = first_field.extractor.to_extract_fn();

                Ok(ValidRule {
                    rule_fn: Box::new(move |t| match extractor_fn(t) {
                        Some(value) => compare_fn(value),
                        None => false,
                    }),
                })
            }
            Match::Field(field_path) => {
                let second_field = get_valid_field_from_class::<T>(
                    T::get_class(),
                    field_path.into(),
                    ExtractorFrom::None,
                )?;

                let ValidatronClassKind::Primitive(second_field_primitive) = second_field.class.into_kind() else {
                        return Err(ValidatronError::ComparingFieldNotPrimitive);
                    };

                if first_field_primitive.field_type_id() == second_field_primitive.field_type_id() {
                    let compare_fn =
                        unsafe { first_field_primitive.compare_fn_any_multi_unchecked(op) }?;

                    let first_extractor_fn = first_field.extractor.to_extract_fn();
                    let second_extractor_fn = second_field.extractor.to_extract_fn();

                    Ok(ValidRule {
                        rule_fn: Box::new(move |t| {
                            match (first_extractor_fn(t), second_extractor_fn(t)) {
                                (Some(v1), Some(v2)) => compare_fn(v1, v2),
                                _ => false,
                            }
                        }),
                    })
                } else {
                    Err(ValidatronError::DifferentFieldsType)
                }
            }
        },

        ValidatronClassKind::Collection(collection) => {
            let Operator::Multi(op) = op else {
                return Err(ValidatronError::OperatorNotAllowedOnType(op, "Collection".to_string())); // TODO: put name of collection
             };

            match value {
                Match::Value(value) => {
                    let compare_fn = match op {
                        MultiOperator::Contains => unsafe {
                            collection.contains_fn_any_value_unchecked(&value)
                        },
                    }?;

                    let extractor_fn = first_field.extractor.to_extract_fn();

                    Ok(ValidRule {
                        rule_fn: Box::new(move |t| match extractor_fn(t) {
                            Some(value) => compare_fn(value),
                            None => false,
                        }),
                    })
                }
                Match::Field(field_path) => {
                    let second_field = get_valid_field_from_class::<T>(
                        T::get_class(),
                        field_path.into(),
                        ExtractorFrom::None,
                    )?;

                    let ValidatronClassKind::Primitive(collection_value_primitive) = collection.get_value_class().into_kind() else {
                        return Err(ValidatronError::CollectionValueNotPrimitive);
                    };

                    let ValidatronClassKind::Primitive(second_field_primitive) = second_field.class.into_kind() else {
                        return Err(ValidatronError::DifferentFieldsType);
                    };

                    if collection_value_primitive.field_type_id()
                        == second_field_primitive.field_type_id()
                    {
                        let compare_fn = unsafe { collection.contains_fn_any_multi_unchecked() }?;

                        let first_extractor_fn = first_field.extractor.to_extract_fn();
                        let second_extractor_fn = second_field.extractor.to_extract_fn();

                        Ok(ValidRule {
                            rule_fn: Box::new(move |t| {
                                match (first_extractor_fn(t), second_extractor_fn(t)) {
                                    (Some(c1), Some(v2)) => compare_fn(c1, v2),
                                    _ => false,
                                }
                            }),
                        })
                    } else {
                        Err(ValidatronError::DifferentFieldsType)
                    }
                }
            }
        }
        _ => unreachable!("Expected only primitive and collection types"),
    };

    vr
}

fn get_valid_field_from_class<T: Validatron + 'static>(
    class: ValidatronClass,
    mut field_path: VecDeque<Field>,
    extractor: ExtractorFrom<T>,
) -> Result<ValidField<T>, ValidatronError> {
    let current_field = field_path.pop_front();

    let Some(current_field) = current_field else {
        return Ok(ValidField{
            class,
            extractor
        });
    };

    // top match field to support methods
    match class.into_kind() {
        ValidatronClassKind::Primitive(_) => {
            Err(ValidatronError::NoMoreFieldsError("primitive".to_string()))
        }
        ValidatronClassKind::Collection(_) => {
            Err(ValidatronError::NoMoreFieldsError("collection".to_string()))
        }
        ValidatronClassKind::Struct(ztruct) => {
            if let Field::Simple { field_name } = current_field {
                if let Some(attribute) = ztruct.get_field_owned(&field_name) {
                    let attribute_class = attribute.get_class();

                    // Wrapping the extractor_fn to uniform with variants
                    let extractor_fn = unsafe { attribute.into_extractor_fn_unchecked() };
                    let extractor_fn: Box<dyn Fn(&dyn Any) -> Option<&dyn Any> + Send + Sync> =
                        Box::new(move |f| Some(extractor_fn(f)));

                    let new_extractor = extractor.chain(extractor_fn);

                    get_valid_field_from_class::<T>(attribute_class, field_path, new_extractor)
                } else {
                    Err(ValidatronError::AttributeNotFound(field_name))
                }
            } else {
                Err(ValidatronError::FieldTypeError("struct".to_string()))
            }
        }
        ValidatronClassKind::Enum(enumz) => {
            if let Field::Adt {
                variant_name,
                field_name,
            } = current_field
            {
                if let Some(variant) = enumz.get_variant_field_owned(&variant_name, &field_name) {
                    let attribute_class = variant.get_class();

                    let extractor_fn = unsafe { variant.into_extractor_fn_unchecked() };

                    let new_extractor = extractor.chain(extractor_fn);

                    get_valid_field_from_class::<T>(attribute_class, field_path, new_extractor)
                } else {
                    Err(ValidatronError::VariantAttributeNotFound(
                        variant_name,
                        field_name,
                    ))
                }
            } else {
                Err(ValidatronError::FieldTypeError("adt".to_string()))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        validator::get_valid_rule, Field, Match, MultiOperator, Operator, RelationalOperator,
        Validatron, ValidatronClass,
    };

    #[test]
    fn test_primitive_identity() {
        let rule = get_valid_rule::<i32>(
            vec![],
            Operator::Relational(RelationalOperator::Equals),
            Match::Value("666".to_string()),
        )
        .unwrap();

        let test = 666;

        assert!(rule.is_match(&test))
    }

    #[test]
    fn test_primitive_in_struct() {
        struct Wrapper {
            i: i32,
        }

        impl Validatron for Wrapper {
            fn get_class() -> ValidatronClass {
                Self::class_builder()
                    .struct_class_builder()
                    .add_field("i", Box::new(|x| &x.i))
                    .build()
            }
        }

        let rule = get_valid_rule::<Wrapper>(
            vec![Field::Simple {
                field_name: "i".to_string(),
            }],
            Operator::Relational(RelationalOperator::Greater),
            Match::Value("42".to_string()),
        )
        .unwrap();

        let test = Wrapper { i: 666 };

        assert!(rule.is_match(&test))
    }

    #[test]
    fn test_primitive_in_struct_dynamic_field() {
        struct Wrapper {
            i: i32,
            second: i32,
        }

        impl Validatron for Wrapper {
            fn get_class() -> ValidatronClass {
                Self::class_builder()
                    .struct_class_builder()
                    .add_field("i", Box::new(|x| &x.i))
                    .add_field("second", Box::new(|x| &x.second))
                    .build()
            }
        }

        let rule = get_valid_rule::<Wrapper>(
            vec![Field::Simple {
                field_name: "i".to_string(),
            }],
            Operator::Relational(RelationalOperator::Greater),
            Match::Field(vec![Field::Simple {
                field_name: "second".to_string(),
            }]),
        )
        .unwrap();

        let test = Wrapper { i: 666, second: 42 };

        assert!(rule.is_match(&test))
    }

    #[test]
    fn test_vec_identity() {
        let rule = get_valid_rule::<Vec<i32>>(
            vec![],
            Operator::Multi(MultiOperator::Contains),
            Match::Value("666".to_string()),
        )
        .unwrap();

        let test = vec![43, 666, 777];

        assert!(rule.is_match(&test))
    }

    #[test]
    fn test_vec_in_struct() {
        struct Wrapper {
            v: Vec<i32>,
        }

        impl Validatron for Wrapper {
            fn get_class() -> ValidatronClass {
                Self::class_builder()
                    .struct_class_builder()
                    .add_field("v", Box::new(|x| &x.v))
                    .build()
            }
        }

        let rule = get_valid_rule::<Wrapper>(
            vec![Field::Simple {
                field_name: "v".to_string(),
            }],
            Operator::Multi(MultiOperator::Contains),
            Match::Value("666".to_string()),
        )
        .unwrap();

        let test = Wrapper {
            v: vec![43, 666, 777],
        };

        assert!(rule.is_match(&test))
    }

    #[test]
    fn test_vec_in_struct_dynamic_field() {
        struct Wrapper {
            i: i32,
            v: Vec<i32>,
        }

        impl Validatron for Wrapper {
            fn get_class() -> ValidatronClass {
                Self::class_builder()
                    .struct_class_builder()
                    .add_field("i", Box::new(|x| &x.i))
                    .add_field("v", Box::new(|x| &x.v))
                    .build()
            }
        }

        let rule = get_valid_rule::<Wrapper>(
            vec![Field::Simple {
                field_name: "v".to_string(),
            }],
            Operator::Multi(MultiOperator::Contains),
            Match::Field(vec![Field::Simple {
                field_name: "i".to_string(),
            }]),
        )
        .unwrap();

        let test = Wrapper {
            i: 666,
            v: vec![43, 666, 777],
        };

        assert!(rule.is_match(&test))
    }

    #[test]
    fn test_nested_struct() {
        #[derive(Debug)]
        struct Inner {
            inner_field: i32,
        }

        impl Validatron for Inner {
            fn get_class() -> ValidatronClass {
                Self::class_builder()
                    .struct_class_builder()
                    .add_field("inner_field", Box::new(|t| &t.inner_field))
                    .build()
            }
        }

        #[derive(Debug)]
        struct Outer {
            inner_struct: Inner,
        }

        impl Validatron for Outer {
            fn get_class() -> ValidatronClass {
                Self::class_builder()
                    .struct_class_builder()
                    .add_field("inner_struct", Box::new(|t| &t.inner_struct))
                    .build()
            }
        }

        let rule = get_valid_rule::<Outer>(
            vec![
                Field::Simple {
                    field_name: "inner_struct".to_string(),
                },
                Field::Simple {
                    field_name: "inner_field".to_string(),
                },
            ],
            Operator::Relational(RelationalOperator::Less),
            Match::Value("666".to_string()),
        )
        .unwrap();

        let test = Outer {
            inner_struct: Inner { inner_field: 42 },
        };

        assert!(rule.is_match(&test))
    }

    #[test]
    fn test_enum_unnamed() {
        #[derive(Debug)]
        #[allow(dead_code)]
        enum MyEnum {
            Unnamed(i32),
            Placeholder,
        }

        impl Validatron for MyEnum {
            fn get_class() -> ValidatronClass {
                Self::class_builder()
                    .enum_class_builder()
                    .add_variant(
                        "Unnamed",
                        "0",
                        Box::new(|t| match &t {
                            MyEnum::Unnamed(i) => Some(i),
                            _ => None,
                        }),
                    )
                    .build()
            }
        }

        let rule = get_valid_rule::<MyEnum>(
            vec![Field::Adt {
                variant_name: "Unnamed".to_string(),
                field_name: "0".to_string(),
            }],
            Operator::Relational(RelationalOperator::Less),
            Match::Value("666".to_string()),
        )
        .unwrap();

        let test = MyEnum::Unnamed(42);

        assert!(rule.is_match(&test))
    }

    #[test]
    fn test_enum_named_plus_struct_plus_dynamic() {
        #[derive(Debug)]
        struct Wrapper {
            small: i32,
            big: i32,
        }

        impl Validatron for Wrapper {
            fn get_class() -> ValidatronClass {
                Self::class_builder()
                    .struct_class_builder()
                    .add_field("small", Box::new(|x| &x.small))
                    .add_field("big", Box::new(|x| &x.big))
                    .build()
            }
        }

        #[derive(Debug)]
        #[allow(dead_code)]
        enum MyEnum {
            Named { inner: Wrapper },
            Placeholder,
        }

        impl Validatron for MyEnum {
            fn get_class() -> ValidatronClass {
                Self::class_builder()
                    .enum_class_builder()
                    .add_variant(
                        "Named",
                        "inner",
                        Box::new(|t| match &t {
                            MyEnum::Named { inner } => Some(inner),
                            _ => None,
                        }),
                    )
                    .build()
            }
        }

        let rule = get_valid_rule::<MyEnum>(
            vec![
                Field::Adt {
                    variant_name: "Named".to_string(),
                    field_name: "inner".to_string(),
                },
                Field::Simple {
                    field_name: "small".to_string(),
                },
            ],
            Operator::Relational(RelationalOperator::Less),
            Match::Field(vec![
                Field::Adt {
                    variant_name: "Named".to_string(),
                    field_name: "inner".to_string(),
                },
                Field::Simple {
                    field_name: "big".to_string(),
                },
            ]),
        )
        .unwrap();

        let test = MyEnum::Named {
            inner: Wrapper {
                small: 42,
                big: 666,
            },
        };

        assert!(rule.is_match(&test))
    }
}
