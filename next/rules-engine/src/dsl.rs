use lalrpop_util::lalrpop_mod;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DslError {
    #[error("Empty list is not allowed")]
    EmptyList,
    #[error("Methods are allowed only as final type")]
    MethodCallNotFinal,
    #[error("Function calls are not supported, only methods are allowed")]
    FunctionCall,
    #[error("Adt fields are not allowed as first field")]
    AdtFirstField,
}

struct OptCheck;

lalrpop_mod!(#[allow(clippy::all)] pub dsl); // syntesized by LALRPOP

#[cfg(test)]
mod tests {
    use validatron::{
        AdtField, Condition, Field, Identifier, MethodCall, Operator, RValue, RelationalOperator,
        SimpleField, StringOperator,
    };

    use super::*;

    #[test]
    fn one_letter_field_start() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"a == 3"#)
            .unwrap();
        let expected = Condition::Binary {
            l: vec![Identifier::Field(Field::Simple(SimpleField(
                "a".to_string(),
            )))],
            op: Operator::Relational(RelationalOperator::Equals),
            r: RValue::Value("3".to_string()),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn one_letter_field_nested_start() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"header.pid == 3"#)
            .unwrap();
        let expected = Condition::Binary {
            l: vec![
                Identifier::Field(Field::Simple(SimpleField("header".to_string()))),
                Identifier::Field(Field::Simple(SimpleField("pid".to_string()))),
            ],
            op: Operator::Relational(RelationalOperator::Equals),
            r: RValue::Value("3".to_string()),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn no_number_field_start() {
        let parsed = dsl::ConditionParser::new().parse("Exec", r#"4ad == 3"#);
        assert!(parsed.is_err());
    }

    #[test]
    fn struct_field_num() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"header.pid == 3"#)
            .unwrap();
        let expected = Condition::Binary {
            l: vec![
                Identifier::Field(Field::Simple(SimpleField("header".to_string()))),
                Identifier::Field(Field::Simple(SimpleField("pid".to_string()))),
            ],
            op: Operator::Relational(RelationalOperator::Equals),
            r: RValue::Value("3".to_string()),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn simple_field_num() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"header == 3"#)
            .unwrap();
        let expected = Condition::Binary {
            l: vec![Identifier::Field(Field::Simple(SimpleField(
                "header".to_string(),
            )))],
            op: Operator::Relational(RelationalOperator::Equals),
            r: RValue::Value("3".to_string()),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn simple_l() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"filename == "/etc/passwd""#)
            .unwrap();
        let expected = Condition::Binary {
            l: vec![Identifier::Field(Field::Simple(SimpleField(
                "filename".to_string(),
            )))],
            op: Operator::Relational(RelationalOperator::Equals),
            r: RValue::Value("/etc/passwd".to_string()),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn simple_field_string() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"image == "systemd""#)
            .unwrap();
        let expected = Condition::Binary {
            l: vec![Identifier::Field(Field::Simple(SimpleField(
                "image".to_string(),
            )))],
            op: Operator::Relational(RelationalOperator::Equals),
            r: RValue::Value("systemd".to_string()),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn simple_field_string_op() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"image STARTS_WITH "systemd""#)
            .unwrap();
        let expected = Condition::Binary {
            l: vec![Identifier::Field(Field::Simple(SimpleField(
                "image".to_string(),
            )))],
            op: Operator::String(StringOperator::StartsWith),
            r: RValue::Value("systemd".to_string()),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn nested_field() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"struct.field.nested == 3"#)
            .unwrap();
        let expected = Condition::Binary {
            l: vec![
                Identifier::Field(Field::Simple(SimpleField("struct".to_string()))),
                Identifier::Field(Field::Simple(SimpleField("field".to_string()))),
                Identifier::Field(Field::Simple(SimpleField("nested".to_string()))),
            ],
            op: Operator::Relational(RelationalOperator::Equals),
            r: RValue::Value("3".to_string()),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn not_condition() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"NOT(header.image != "/usr/bin/sshd")"#)
            .unwrap();
        let expected = Condition::Not {
            inner: Box::new(Condition::Binary {
                l: vec![
                    Identifier::Field(Field::Simple(SimpleField("header".to_string()))),
                    Identifier::Field(Field::Simple(SimpleField("image".to_string()))),
                ],
                op: Operator::Relational(RelationalOperator::NotEquals),
                r: RValue::Value("/usr/bin/sshd".to_string()),
            }),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn not_condition_space() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"NOT (header.image != "/usr/bin/sshd")"#)
            .unwrap();
        let expected = Condition::Not {
            inner: Box::new(Condition::Binary {
                l: vec![
                    Identifier::Field(Field::Simple(SimpleField("header".to_string()))),
                    Identifier::Field(Field::Simple(SimpleField("image".to_string()))),
                ],
                op: Operator::Relational(RelationalOperator::NotEquals),
                r: RValue::Value("/usr/bin/sshd".to_string()),
            }),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn and_condition() {
        let parsed = dsl::ConditionParser::new()
            .parse(
                "Exec",
                r#"header.image != "/usr/bin/sshd" AND payload.filename == "/etc/shadow""#,
            )
            .unwrap();
        let expected = Condition::And {
            l: Box::new(Condition::Binary {
                l: vec![
                    Identifier::Field(Field::Simple(SimpleField("header".to_string()))),
                    Identifier::Field(Field::Simple(SimpleField("image".to_string()))),
                ],
                op: Operator::Relational(RelationalOperator::NotEquals),
                r: RValue::Value("/usr/bin/sshd".to_string()),
            }),
            r: Box::new(Condition::Binary {
                l: vec![
                    Identifier::Field(Field::Simple(SimpleField("payload".to_string()))),
                    Identifier::Field(Field::Adt(AdtField {
                        variant_name: "Exec".to_string(),
                        field_name: "filename".to_string(),
                    })),
                ],
                op: Operator::Relational(RelationalOperator::Equals),
                r: RValue::Value("/etc/shadow".to_string()),
            }),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn or_condition() {
        let parsed = dsl::ConditionParser::new()
            .parse(
                "FileOpen",
                r#"header.image != "/usr/bin/sshd" OR payload.filename == "/etc/shadow""#,
            )
            .unwrap();
        let expected = Condition::Or {
            l: Box::new(Condition::Binary {
                l: vec![
                    Identifier::Field(Field::Simple(SimpleField("header".to_string()))),
                    Identifier::Field(Field::Simple(SimpleField("image".to_string()))),
                ],
                op: Operator::Relational(RelationalOperator::NotEquals),
                r: RValue::Value("/usr/bin/sshd".to_string()),
            }),
            r: Box::new(Condition::Binary {
                l: vec![
                    Identifier::Field(Field::Simple(SimpleField("payload".to_string()))),
                    Identifier::Field(Field::Adt(AdtField {
                        variant_name: "FileOpen".to_string(),
                        field_name: "filename".to_string(),
                    })),
                ],
                op: Operator::Relational(RelationalOperator::Equals),
                r: RValue::Value("/etc/shadow".to_string()),
            }),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn complex_condition() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec",r#"header.image == "/usr/bin/sshd" OR NOT(header.image == "/usr/bin/cat" AND payload.filename == "/etc/passwd")"#)
            .unwrap();
        let expected = Condition::Or {
            l: Box::new(Condition::Binary {
                l: vec![
                    Identifier::Field(Field::Simple(SimpleField("header".to_string()))),
                    Identifier::Field(Field::Simple(SimpleField("image".to_string()))),
                ],
                op: Operator::Relational(RelationalOperator::Equals),
                r: RValue::Value("/usr/bin/sshd".to_string()),
            }),
            r: Box::new(Condition::Not {
                inner: Box::new(Condition::And {
                    l: Box::new(Condition::Binary {
                        l: vec![
                            Identifier::Field(Field::Simple(SimpleField("header".to_string()))),
                            Identifier::Field(Field::Simple(SimpleField("image".to_string()))),
                        ],
                        op: Operator::Relational(RelationalOperator::Equals),
                        r: RValue::Value("/usr/bin/cat".to_string()),
                    }),
                    r: Box::new(Condition::Binary {
                        l: vec![
                            Identifier::Field(Field::Simple(SimpleField("payload".to_string()))),
                            Identifier::Field(Field::Adt(AdtField {
                                variant_name: "Exec".to_string(),
                                field_name: "filename".to_string(),
                            })),
                        ],
                        op: Operator::Relational(RelationalOperator::Equals),
                        r: RValue::Value("/etc/passwd".to_string()),
                    }),
                }),
            }),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn list_single_string() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"header.image IN ["/usr/bin/cat"]"#)
            .unwrap();
        let expected = Condition::Binary {
            l: vec![
                Identifier::Field(Field::Simple(SimpleField("header".to_string()))),
                Identifier::Field(Field::Simple(SimpleField("image".to_string()))),
            ],
            op: Operator::Relational(RelationalOperator::Equals),
            r: RValue::Value("/usr/bin/cat".to_string()),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn list_two_num() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"header.pid IN [4,2]"#)
            .unwrap();
        let expected = Condition::Or {
            l: Box::new(Condition::Binary {
                l: vec![
                    Identifier::Field(Field::Simple(SimpleField("header".to_string()))),
                    Identifier::Field(Field::Simple(SimpleField("pid".to_string()))),
                ],
                op: Operator::Relational(RelationalOperator::Equals),
                r: RValue::Value("4".to_string()),
            }),
            r: Box::new(Condition::Binary {
                l: vec![
                    Identifier::Field(Field::Simple(SimpleField("header".to_string()))),
                    Identifier::Field(Field::Simple(SimpleField("pid".to_string()))),
                ],
                op: Operator::Relational(RelationalOperator::Equals),
                r: RValue::Value("2".to_string()),
            }),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn list_three_num() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"header.pid IN [6,6,6]"#)
            .unwrap();
        let expected = Condition::Or {
            l: Box::new(Condition::Or {
                l: Box::new(Condition::Binary {
                    l: vec![
                        Identifier::Field(Field::Simple(SimpleField("header".to_string()))),
                        Identifier::Field(Field::Simple(SimpleField("pid".to_string()))),
                    ],
                    op: Operator::Relational(RelationalOperator::Equals),
                    r: RValue::Value("6".to_string()),
                }),
                r: Box::new(Condition::Binary {
                    l: vec![
                        Identifier::Field(Field::Simple(SimpleField("header".to_string()))),
                        Identifier::Field(Field::Simple(SimpleField("pid".to_string()))),
                    ],
                    op: Operator::Relational(RelationalOperator::Equals),
                    r: RValue::Value("6".to_string()),
                }),
            }),
            r: Box::new(Condition::Binary {
                l: vec![
                    Identifier::Field(Field::Simple(SimpleField("header".to_string()))),
                    Identifier::Field(Field::Simple(SimpleField("pid".to_string()))),
                ],
                op: Operator::Relational(RelationalOperator::Equals),
                r: RValue::Value("6".to_string()),
            }),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn list_void() {
        let parsed = dsl::ConditionParser::new().parse("Exec", r#"header.pid IN []"#);
        assert!(parsed.is_err());
    }

    #[test]
    fn simple_field_compare() {
        let parsed = dsl::ConditionParser::new()
            .parse("FileDelete", r#"header.image == payload.filename"#)
            .unwrap();
        let expected = Condition::Binary {
            l: vec![
                Identifier::Field(Field::Simple(SimpleField("header".to_string()))),
                Identifier::Field(Field::Simple(SimpleField("image".to_string()))),
            ],
            op: Operator::Relational(RelationalOperator::Equals),
            r: RValue::Identifier(vec![
                Identifier::Field(Field::Simple(SimpleField("payload".to_string()))),
                Identifier::Field(Field::Adt(AdtField {
                    variant_name: "FileDelete".to_string(),
                    field_name: "filename".to_string(),
                })),
            ]),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn one_character_value_start() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"a == "3""#)
            .unwrap();
        let expected = Condition::Binary {
            l: vec![Identifier::Field(Field::Simple(SimpleField(
                "a".to_string(),
            )))],
            op: Operator::Relational(RelationalOperator::Equals),
            r: RValue::Value("3".to_string()),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn single_method_call() {
        let parsed = dsl::ConditionParser::new()
            .parse("FileExec", r#"header.container.is_some()"#)
            .unwrap();
        let expected = Condition::Unary(vec![
            Identifier::Field(Field::Simple(SimpleField("header".to_string()))),
            Identifier::Field(Field::Simple(SimpleField("container".to_string()))),
            Identifier::MethodCall(MethodCall {
                name: "is_some".to_string(),
            }),
        ]);
        assert_eq!(parsed, expected);
    }

    #[test]
    fn option_field() {
        let parsed = dsl::ConditionParser::new()
            .parse("FileExec", r#"header.container?.name == "ubuntu""#)
            .unwrap();
        let expected = Condition::Binary {
            l: vec![
                Identifier::Field(Field::Simple(SimpleField("header".to_string()))),
                Identifier::Field(Field::Simple(SimpleField("container".to_string()))),
                Identifier::Field(Field::Adt(AdtField {
                    variant_name: "Some".to_string(),
                    field_name: "0".to_string(),
                })),
                Identifier::Field(Field::Simple(SimpleField("name".to_string()))),
            ],
            op: Operator::Relational(RelationalOperator::Equals),
            r: RValue::Value("ubuntu".to_string()),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn option_nested_field() {
        let parsed = dsl::ConditionParser::new()
            .parse("FileExec", r#"header.prop1?.prop2.prop3?.prop4 == "good""#)
            .unwrap();
        let expected = Condition::Binary {
            l: vec![
                Identifier::Field(Field::Simple(SimpleField("header".to_string()))),
                Identifier::Field(Field::Simple(SimpleField("prop1".to_string()))),
                Identifier::Field(Field::Adt(AdtField {
                    variant_name: "Some".to_string(),
                    field_name: "0".to_string(),
                })),
                Identifier::Field(Field::Simple(SimpleField("prop2".to_string()))),
                Identifier::Field(Field::Simple(SimpleField("prop3".to_string()))),
                Identifier::Field(Field::Adt(AdtField {
                    variant_name: "Some".to_string(),
                    field_name: "0".to_string(),
                })),
                Identifier::Field(Field::Simple(SimpleField("prop4".to_string()))),
            ],
            op: Operator::Relational(RelationalOperator::Equals),
            r: RValue::Value("good".to_string()),
        };
        assert_eq!(parsed, expected);
    }
}
