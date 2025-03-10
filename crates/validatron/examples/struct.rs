use std::error::Error;

use validatron::{
    Field, Identifier, Operator, RValue, RelationalOperator, SimpleField, Validatron,
    validator::get_valid_rule,
};

#[derive(Debug, Clone, Validatron)]
pub struct MyStruct {
    pub a: i32,
    pub b: i32,
    pub c: i32,
}

/// Match the field "a" against the fixed value "111" using the "Equals" operator
fn fixed_match(test: &MyStruct) -> Result<bool, Box<dyn Error>> {
    let rule = get_valid_rule::<MyStruct>(
        vec![Identifier::Field(Field::Simple(SimpleField(
            "a".to_string(),
        )))],
        Operator::Relational(RelationalOperator::Equals),
        RValue::Value("111".to_string()),
    )?;

    Ok(rule.is_match(test))
}

/// Match the field "a" against the field "b" using the "Greater" operator
fn dynamic_match(test: &MyStruct) -> Result<bool, Box<dyn Error>> {
    let rule = get_valid_rule::<MyStruct>(
        vec![Identifier::Field(Field::Simple(SimpleField(
            "a".to_string(),
        )))],
        Operator::Relational(RelationalOperator::Greater),
        RValue::Identifier(vec![Identifier::Field(Field::Simple(SimpleField(
            "b".to_string(),
        )))]),
    )?;

    Ok(rule.is_match(test))
}

fn main() {
    let test = MyStruct {
        a: 111,
        b: 222,
        c: 333,
    };

    assert!(fixed_match(&test).unwrap());

    assert!(!dynamic_match(&test).unwrap());
}
