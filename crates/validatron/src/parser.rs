use std::{fmt::Display, str::FromStr};

use lalrpop_util::lalrpop_mod;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::Operator;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub r#type: String,
    pub condition: Condition,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    Base {
        field: Field,
        op: Operator,
        value: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "content")]
pub enum Field {
    Simple(String),
    Struct {
        name: String,
        inner_field: Box<Field>,
    },
}

impl Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Field::Simple(name) => write!(f, "{name}"),
            Field::Struct { name, inner_field } => write!(f, "{name}.{}", inner_field),
        }
    }
}

impl FromStr for Field {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let split_by_dot = s.split('.').collect::<Vec<&str>>();

        let mut reversed = split_by_dot.iter().rev();

        let first = reversed
            .next()
            .ok_or("Field should have a least one character except '.'")?;

        let root = Field::Simple(first.to_string());

        let composed = reversed.fold(root, |acc, curr| Field::Struct {
            name: curr.to_string(),
            inner_field: Box::new(acc),
        });

        Ok(composed)
    }
}

#[derive(Error, Debug)]
pub enum DslError {
    #[error("Empty list is not allowed")]
    EmptyList,
    #[error("Error parsing field {field}: {cause}")]
    Field { field: String, cause: String },
}

lalrpop_mod!(#[allow(clippy::all)] pub dsl); // syntesized by LALRPOP

#[cfg(test)]
mod tests {
    use crate::{RelationalOperator, StringOperator};

    use super::*;

    #[test]
    fn struct_field_num() {
        let parsed = dsl::ConditionParser::new()
            .parse(r#"header.pid == 3"#)
            .unwrap();
        let expected = Condition::Base {
            field: Field::Struct {
                name: "header".to_string(),
                inner_field: Box::new(Field::Simple("pid".to_string())),
            },
            op: Operator::Relational(RelationalOperator::Equals),
            value: "3".to_string(),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn simple_field_num() {
        let parsed = dsl::ConditionParser::new().parse(r#"header == 3"#).unwrap();
        let expected = Condition::Base {
            field: Field::Simple("header".to_string()),
            op: Operator::Relational(RelationalOperator::Equals),
            value: "3".to_string(),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn simple_field_path() {
        let parsed = dsl::ConditionParser::new()
            .parse(r#"filename == "/etc/passwd""#)
            .unwrap();
        let expected = Condition::Base {
            field: Field::Simple("filename".to_string()),
            op: Operator::Relational(RelationalOperator::Equals),
            value: "/etc/passwd".to_string(),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn simple_field_string() {
        let parsed = dsl::ConditionParser::new()
            .parse(r#"image == "systemd""#)
            .unwrap();
        let expected = Condition::Base {
            field: Field::Simple("image".to_string()),
            op: Operator::Relational(RelationalOperator::Equals),
            value: "systemd".to_string(),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn simple_field_string_op() {
        let parsed = dsl::ConditionParser::new()
            .parse(r#"image STARTS_WITH "systemd""#)
            .unwrap();
        let expected = Condition::Base {
            field: Field::Simple("image".to_string()),
            op: Operator::String(StringOperator::StartsWith),
            value: "systemd".to_string(),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn nested_field() {
        let parsed = dsl::ConditionParser::new()
            .parse(r#"struct.field.nested == 3"#)
            .unwrap();
        let expected = Condition::Base {
            field: Field::Struct {
                name: "struct".to_string(),
                inner_field: Box::new(Field::Struct {
                    name: "field".to_string(),
                    inner_field: Box::new(Field::Simple("nested".to_string())),
                }),
            },
            op: Operator::Relational(RelationalOperator::Equals),
            value: "3".to_string(),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn not_condition() {
        let parsed = dsl::ConditionParser::new()
            .parse(r#"NOT(header.image != "/usr/bin/sshd")"#)
            .unwrap();
        let expected = Condition::Not {
            inner: Box::new(Condition::Base {
                field: Field::Struct {
                    name: "header".to_string(),
                    inner_field: Box::new(Field::Simple("image".to_string())),
                },
                op: Operator::Relational(RelationalOperator::NotEquals),
                value: "/usr/bin/sshd".to_string(),
            }),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn not_condition_space() {
        let parsed = dsl::ConditionParser::new()
            .parse(r#"NOT (header.image != "/usr/bin/sshd")"#)
            .unwrap();
        let expected = Condition::Not {
            inner: Box::new(Condition::Base {
                field: Field::Struct {
                    name: "header".to_string(),
                    inner_field: Box::new(Field::Simple("image".to_string())),
                },
                op: Operator::Relational(RelationalOperator::NotEquals),
                value: "/usr/bin/sshd".to_string(),
            }),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn and_condition() {
        let parsed = dsl::ConditionParser::new()
            .parse(r#"header.image != "/usr/bin/sshd" AND payload.filename == "/etc/shadow""#)
            .unwrap();
        let expected = Condition::And {
            l: Box::new(Condition::Base {
                field: Field::Struct {
                    name: "header".to_string(),
                    inner_field: Box::new(Field::Simple("image".to_string())),
                },
                op: Operator::Relational(RelationalOperator::NotEquals),
                value: "/usr/bin/sshd".to_string(),
            }),
            r: Box::new(Condition::Base {
                field: Field::Struct {
                    name: "payload".to_string(),
                    inner_field: Box::new(Field::Simple("filename".to_string())),
                },
                op: Operator::Relational(RelationalOperator::Equals),
                value: "/etc/shadow".to_string(),
            }),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn or_condition() {
        let parsed = dsl::ConditionParser::new()
            .parse(r#"header.image != "/usr/bin/sshd" OR payload.filename == "/etc/shadow""#)
            .unwrap();
        let expected = Condition::Or {
            l: Box::new(Condition::Base {
                field: Field::Struct {
                    name: "header".to_string(),
                    inner_field: Box::new(Field::Simple("image".to_string())),
                },
                op: Operator::Relational(RelationalOperator::NotEquals),
                value: "/usr/bin/sshd".to_string(),
            }),
            r: Box::new(Condition::Base {
                field: Field::Struct {
                    name: "payload".to_string(),
                    inner_field: Box::new(Field::Simple("filename".to_string())),
                },
                op: Operator::Relational(RelationalOperator::Equals),
                value: "/etc/shadow".to_string(),
            }),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn complex_condition() {
        let parsed = dsl::ConditionParser::new()
            .parse(r#"header.image == "/usr/bin/sshd" OR NOT(header.image == "/usr/bin/cat" AND payload.filename == "/etc/passwd")"#)
            .unwrap();
        let expected = Condition::Or {
            l: Box::new(Condition::Base {
                field: Field::Struct {
                    name: "header".to_string(),
                    inner_field: Box::new(Field::Simple("image".to_string())),
                },
                op: Operator::Relational(RelationalOperator::Equals),
                value: "/usr/bin/sshd".to_string(),
            }),
            r: Box::new(Condition::Not {
                inner: Box::new(Condition::And {
                    l: Box::new(Condition::Base {
                        field: Field::Struct {
                            name: "header".to_string(),
                            inner_field: Box::new(Field::Simple("image".to_string())),
                        },
                        op: Operator::Relational(RelationalOperator::Equals),
                        value: "/usr/bin/cat".to_string(),
                    }),
                    r: Box::new(Condition::Base {
                        field: Field::Struct {
                            name: "payload".to_string(),
                            inner_field: Box::new(Field::Simple("filename".to_string())),
                        },
                        op: Operator::Relational(RelationalOperator::Equals),
                        value: "/etc/passwd".to_string(),
                    }),
                }),
            }),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn list_single_string() {
        let parsed = dsl::ConditionParser::new()
            .parse(r#"header.image IN ["/usr/bin/cat"]"#)
            .unwrap();
        let expected = Condition::Base {
            field: Field::Struct {
                name: "header".to_string(),
                inner_field: Box::new(Field::Simple("image".to_string())),
            },
            op: Operator::Relational(RelationalOperator::Equals),
            value: "/usr/bin/cat".to_string(),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn list_two_num() {
        let parsed = dsl::ConditionParser::new()
            .parse(r#"header.pid IN [4,2]"#)
            .unwrap();
        let expected = Condition::Or {
            l: Box::new(Condition::Base {
                field: Field::Struct {
                    name: "header".to_string(),
                    inner_field: Box::new(Field::Simple("pid".to_string())),
                },
                op: Operator::Relational(RelationalOperator::Equals),
                value: "4".to_string(),
            }),
            r: Box::new(Condition::Base {
                field: Field::Struct {
                    name: "header".to_string(),
                    inner_field: Box::new(Field::Simple("pid".to_string())),
                },
                op: Operator::Relational(RelationalOperator::Equals),
                value: "2".to_string(),
            }),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn list_three_num() {
        let parsed = dsl::ConditionParser::new()
            .parse(r#"header.pid IN [6,6,6]"#)
            .unwrap();
        let expected = Condition::Or {
            l: Box::new(Condition::Or {
                l: Box::new(Condition::Base {
                    field: Field::Struct {
                        name: "header".to_string(),
                        inner_field: Box::new(Field::Simple("pid".to_string())),
                    },
                    op: Operator::Relational(RelationalOperator::Equals),
                    value: "6".to_string(),
                }),
                r: Box::new(Condition::Base {
                    field: Field::Struct {
                        name: "header".to_string(),
                        inner_field: Box::new(Field::Simple("pid".to_string())),
                    },
                    op: Operator::Relational(RelationalOperator::Equals),
                    value: "6".to_string(),
                }),
            }),
            r: Box::new(Condition::Base {
                field: Field::Struct {
                    name: "header".to_string(),
                    inner_field: Box::new(Field::Simple("pid".to_string())),
                },
                op: Operator::Relational(RelationalOperator::Equals),
                value: "6".to_string(),
            }),
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn list_void() {
        let parsed = dsl::ConditionParser::new().parse(r#"header.pid IN []"#);
        assert!(parsed.is_err());
    }
}
