# Validatron

Validatron is a type checked condition framework to build complex rules for complex types. it's the base of the Pulsar's `rule-engine` module.

Basically it's a way for check the correctness of rules over types and subsequent compilation into a single function.

It check if fields specified in a rules are valid for a given type. Example:

```rust
use validatron::validator::{get_valid_rule, Operator, RelationalOperator, Identifier, Field, RValue, SimpleField};
#[derive(Validatron)]
struct MyStruct {
    my_value: i32
}
let rule = get_valid_rule::<MyStruct>(
    vec![Identifier::Field(Field::Simple(SimpleField(
        "my_value".to_string()
    )))],
    Operator::Relational(RelationalOperator::Equals),
    RValue::Value("42".to_string()),
)
.unwrap();
let test = MyStruct { my_value: 42 };
assert!(rule.is_match(&test))
```

It will check if the field `my_value` exists in the `MyStruct` type and if it's possible to parse the input string `"42"` into the
specific field type (`i32`).

On top of this it's possible to write complex rules, assembling conditions with logical operators (AND, OR, NOT). Example:

```rust
use validatron::{Ruleset, Rule, Validatron, Operator, RelationalOperator, Condition, Identifier, Field, RValue, SimpleField};
#[derive(Validatron)]
struct MyStruct {
    my_value: i32,
}
let ruleset: Ruleset<MyStruct> = Ruleset::from_rules(vec![
    Rule {
        name: "my_value equal to 3 or 5".to_string(),
        condition: Condition::Or {
            l: Box::new(Condition::Binary {
                l: vec![Identifier::Field(Field::Simple(SimpleField(
                    "my_value".to_string()
                )))],
                op: Operator::Relational(RelationalOperator::Equals),
                r: RValue::Value("3".to_string()),
            }),
            r: Box::new(Condition::Binary {
                l: vec![Identifier::Field(Field::Simple(SimpleField(
                    "my_value".to_string()
                )))],
                op: Operator::Relational(RelationalOperator::Equals),
                r: RValue::Value("5".to_string()),
            }),
        },
    },
    Rule {
        name: "my_value greater than 100".to_string(),
        condition: Condition::Binary {
            l: vec![Identifier::Field(Field::Simple(SimpleField(
                "my_value".to_string()
            )))],
            op: Operator::Relational(RelationalOperator::Greater),
            r: RValue::Value("100".to_string()),
        },
    },
])
.unwrap();
let test = MyStruct {
    my_value: 42
};
ruleset.run(&test, |rule| {
    println!("Matched rule {}", rule.name)
})
```

Check the [ruleset](./examples/ruleset.rs) module for more details.

To better understand the underlying implementation, take a look at the [reflection](./src/reflection.rs) module.

It includes [macros](./derive/README.md) to generate implementations of the required traits.

### Closures for code generation

For the runtime it compiles rules using closures to generate code. It walks AST nodes and generates closures recursively [^1].

## Status

Now have the base functionalities needed by Pulsar. Missing features are work in progress. 

## Contributing

If you're interested in contributing to Validatron: thank you!

We have a [contributing guide](../../CONTRIBUTING.md) which will help you getting involved in the Validatron project.

## Building Validatron

Validatron uses a [conventional Cargo build process](https://doc.rust-lang.org/cargo/guide/working-on-an-existing-project.html). 

Validatron uses a [Cargo Workspace](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html), so for some cargo commands, such as `cargo test`, the `--all` is needed to tell cargo to visit all of the crates.


[^1]: Marc Feeley, Guy Lapalme, [Using closures for code generation](https://doi.org/10.1016/0096-0551(87)90012-9)