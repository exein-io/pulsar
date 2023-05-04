use std::error::Error;

use validatron::{
    validator::get_valid_rule, Field, Match, Operator, RelationalOperator, Validatron,
    ValidatronClass,
};

#[derive(Debug, Clone)]
pub struct MyStruct {
    pub a: i32,
    pub b: i32,
    pub c: i32,
}

impl Validatron for MyStruct {
    fn get_class() -> ValidatronClass {
        Self::class_builder()
            .struct_class_builder()
            .add_field("a", Box::new(|t| &t.a))
            .add_field("b", Box::new(|t| &t.b))
            .add_field("c", Box::new(|t| &t.c))
            .build()
    }
}
/// Match the field "a" against the fixed value "111" using the "Equals" operator
fn fixed_match(test: &MyStruct) -> Result<bool, Box<dyn Error>> {
    let rule = get_valid_rule::<MyStruct>(
        vec![Field::Simple {
            field_name: "a".to_string(),
        }],
        Operator::Relational(RelationalOperator::Equals),
        Match::Value("111".to_string()),
    )?;

    Ok(rule.is_match(&test))
}

/// Match the field "a" against the field "b" using the "Greater" operator
fn dynamic_match(test: &MyStruct) -> Result<bool, Box<dyn Error>> {
    let rule = get_valid_rule::<MyStruct>(
        vec![Field::Simple {
            field_name: "a".to_string(),
        }],
        Operator::Relational(RelationalOperator::Greater),
        Match::Field(vec![Field::Simple {
            field_name: "b".to_string(),
        }]),
    )?;

    Ok(rule.is_match(&test))
}

fn main() {
    let test = MyStruct {
        a: 111,
        b: 222,
        c: 333,
    };

    assert_eq!(fixed_match(&test).unwrap(), true);

    assert_eq!(dynamic_match(&test).unwrap(), false);
}
