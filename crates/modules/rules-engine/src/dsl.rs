use lalrpop_util::lalrpop_mod;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DslError {
    #[error("Empty list is not allowed")]
    EmptyList,
}

lalrpop_mod!(#[allow(clippy::all)] pub dsl); // syntesized by LALRPOP

#[cfg(test)]
mod tests {
    use validatron::{Condition, Field, Match, Operator, RelationalOperator, StringOperator};

    use super::*;

    #[test]
    fn one_letter_field_start() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"a == 3"#)
            .unwrap();
        let expected = Condition::Base {
            field_path: vec![Field::Simple {
                field_name: "a".to_string(),
            }],
            op: Operator::Relational(RelationalOperator::Equals),
            value: Match::Value("3".to_string()),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn one_letter_field_nested_start() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"header.pid == 3"#)
            .unwrap();
        let expected = Condition::Base {
            field_path: vec![
                Field::Simple {
                    field_name: "header".to_string(),
                },
                Field::Simple {
                    field_name: "pid".to_string(),
                },
            ],
            op: Operator::Relational(RelationalOperator::Equals),
            value: Match::Value("3".to_string()),
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
        let expected = Condition::Base {
            field_path: vec![
                Field::Simple {
                    field_name: "header".to_string(),
                },
                Field::Simple {
                    field_name: "pid".to_string(),
                },
            ],
            op: Operator::Relational(RelationalOperator::Equals),
            value: Match::Value("3".to_string()),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn simple_field_num() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"header == 3"#)
            .unwrap();
        let expected = Condition::Base {
            field_path: vec![Field::Simple {
                field_name: "header".to_string(),
            }],
            op: Operator::Relational(RelationalOperator::Equals),
            value: Match::Value("3".to_string()),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn simple_field_path() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"filename == "/etc/passwd""#)
            .unwrap();
        let expected = Condition::Base {
            field_path: vec![Field::Simple {
                field_name: "filename".to_string(),
            }],
            op: Operator::Relational(RelationalOperator::Equals),
            value: Match::Value("/etc/passwd".to_string()),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn simple_field_string() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"image == "systemd""#)
            .unwrap();
        let expected = Condition::Base {
            field_path: vec![Field::Simple {
                field_name: "image".to_string(),
            }],
            op: Operator::Relational(RelationalOperator::Equals),
            value: Match::Value("systemd".to_string()),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn simple_field_string_op() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"image STARTS_WITH "systemd""#)
            .unwrap();
        let expected = Condition::Base {
            field_path: vec![Field::Simple {
                field_name: "image".to_string(),
            }],
            op: Operator::String(StringOperator::StartsWith),
            value: Match::Value("systemd".to_string()),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn nested_field() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"struct.field.nested == 3"#)
            .unwrap();
        let expected = Condition::Base {
            field_path: vec![
                Field::Simple {
                    field_name: "struct".to_string(),
                },
                Field::Simple {
                    field_name: "field".to_string(),
                },
                Field::Simple {
                    field_name: "nested".to_string(),
                },
            ],
            op: Operator::Relational(RelationalOperator::Equals),
            value: Match::Value("3".to_string()),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn not_condition() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"NOT(header.image != "/usr/bin/sshd")"#)
            .unwrap();
        let expected = Condition::Not {
            inner: Box::new(Condition::Base {
                field_path: vec![
                    Field::Simple {
                        field_name: "header".to_string(),
                    },
                    Field::Simple {
                        field_name: "image".to_string(),
                    },
                ],
                op: Operator::Relational(RelationalOperator::NotEquals),
                value: Match::Value("/usr/bin/sshd".to_string()),
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
            inner: Box::new(Condition::Base {
                field_path: vec![
                    Field::Simple {
                        field_name: "header".to_string(),
                    },
                    Field::Simple {
                        field_name: "image".to_string(),
                    },
                ],
                op: Operator::Relational(RelationalOperator::NotEquals),
                value: Match::Value("/usr/bin/sshd".to_string()),
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
            l: Box::new(Condition::Base {
                field_path: vec![
                    Field::Simple {
                        field_name: "header".to_string(),
                    },
                    Field::Simple {
                        field_name: "image".to_string(),
                    },
                ],
                op: Operator::Relational(RelationalOperator::NotEquals),
                value: Match::Value("/usr/bin/sshd".to_string()),
            }),
            r: Box::new(Condition::Base {
                field_path: vec![
                    Field::Simple {
                        field_name: "payload".to_string(),
                    },
                    Field::Adt {
                        variant_name: "Exec".to_string(),
                        field_name: "filename".to_string(),
                    },
                ],
                op: Operator::Relational(RelationalOperator::Equals),
                value: Match::Value("/etc/shadow".to_string()),
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
            l: Box::new(Condition::Base {
                field_path: vec![
                    Field::Simple {
                        field_name: "header".to_string(),
                    },
                    Field::Simple {
                        field_name: "image".to_string(),
                    },
                ],
                op: Operator::Relational(RelationalOperator::NotEquals),
                value: Match::Value("/usr/bin/sshd".to_string()),
            }),
            r: Box::new(Condition::Base {
                field_path: vec![
                    Field::Simple {
                        field_name: "payload".to_string(),
                    },
                    Field::Adt {
                        variant_name: "FileOpen".to_string(),
                        field_name: "filename".to_string(),
                    },
                ],
                op: Operator::Relational(RelationalOperator::Equals),
                value: Match::Value("/etc/shadow".to_string()),
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
            l: Box::new(Condition::Base {
                field_path: vec![
                    Field::Simple {
                        field_name: "header".to_string(),
                    },
                    Field::Simple {
                        field_name: "image".to_string(),
                    },
                ],
                op: Operator::Relational(RelationalOperator::Equals),
                value: Match::Value("/usr/bin/sshd".to_string()),
            }),
            r: Box::new(Condition::Not {
                inner: Box::new(Condition::And {
                    l: Box::new(Condition::Base {
                        field_path: vec![
                            Field::Simple {
                                field_name: "header".to_string(),
                            },
                            Field::Simple {
                                field_name: "image".to_string(),
                            },
                        ],
                        op: Operator::Relational(RelationalOperator::Equals),
                        value: Match::Value("/usr/bin/cat".to_string()),
                    }),
                    r: Box::new(Condition::Base {
                        field_path: vec![
                            Field::Simple {
                                field_name: "payload".to_string(),
                            },
                            Field::Adt {
                                variant_name: "Exec".to_string(),
                                field_name: "filename".to_string(),
                            },
                        ],
                        op: Operator::Relational(RelationalOperator::Equals),
                        value: Match::Value("/etc/passwd".to_string()),
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
        let expected = Condition::Base {
            field_path: vec![
                Field::Simple {
                    field_name: "header".to_string(),
                },
                Field::Simple {
                    field_name: "image".to_string(),
                },
            ],
            op: Operator::Relational(RelationalOperator::Equals),
            value: Match::Value("/usr/bin/cat".to_string()),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn list_two_num() {
        let parsed = dsl::ConditionParser::new()
            .parse("Exec", r#"header.pid IN [4,2]"#)
            .unwrap();
        let expected = Condition::Or {
            l: Box::new(Condition::Base {
                field_path: vec![
                    Field::Simple {
                        field_name: "header".to_string(),
                    },
                    Field::Simple {
                        field_name: "pid".to_string(),
                    },
                ],
                op: Operator::Relational(RelationalOperator::Equals),
                value: Match::Value("4".to_string()),
            }),
            r: Box::new(Condition::Base {
                field_path: vec![
                    Field::Simple {
                        field_name: "header".to_string(),
                    },
                    Field::Simple {
                        field_name: "pid".to_string(),
                    },
                ],
                op: Operator::Relational(RelationalOperator::Equals),
                value: Match::Value("2".to_string()),
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
                l: Box::new(Condition::Base {
                    field_path: vec![
                        Field::Simple {
                            field_name: "header".to_string(),
                        },
                        Field::Simple {
                            field_name: "pid".to_string(),
                        },
                    ],
                    op: Operator::Relational(RelationalOperator::Equals),
                    value: Match::Value("6".to_string()),
                }),
                r: Box::new(Condition::Base {
                    field_path: vec![
                        Field::Simple {
                            field_name: "header".to_string(),
                        },
                        Field::Simple {
                            field_name: "pid".to_string(),
                        },
                    ],
                    op: Operator::Relational(RelationalOperator::Equals),
                    value: Match::Value("6".to_string()),
                }),
            }),
            r: Box::new(Condition::Base {
                field_path: vec![
                    Field::Simple {
                        field_name: "header".to_string(),
                    },
                    Field::Simple {
                        field_name: "pid".to_string(),
                    },
                ],
                op: Operator::Relational(RelationalOperator::Equals),
                value: Match::Value("6".to_string()),
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
        let expected = Condition::Base {
            field_path: vec![
                Field::Simple {
                    field_name: "header".to_string(),
                },
                Field::Simple {
                    field_name: "image".to_string(),
                },
            ],
            op: Operator::Relational(RelationalOperator::Equals),
            value: Match::Field(vec![
                Field::Simple {
                    field_name: "payload".to_string(),
                },
                Field::Adt {
                    variant_name: "FileDelete".to_string(),
                    field_name: "filename".to_string(),
                },
            ]),
        };
        assert_eq!(parsed, expected);
    }
}
