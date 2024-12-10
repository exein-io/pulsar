use validatron::{
    CompiledRule, Identifier, Operator, RelationalOperator, Rule, SimpleField, Validatron,
    ValidatronError,
};

/// Set of rules which can be applied over any instance of type `T`.
///
/// Each rule has been validated and compiled into single closure.
pub struct Ruleset<T: Validatron + 'static> {
    pub(crate) rules: Vec<CompiledRule<T>>,
}

impl<T: Validatron> Ruleset<T> {
    /// Create a ruleset from a [Vec] of [CompiledRule].
    pub fn from_compiled(rules: Vec<CompiledRule<T>>) -> Self {
        Self { rules }
    }

    /// Try to create a ruleset from a [Vec] of [Rule].
    ///
    /// The rules will be validated and compiled to an optimized form.
    pub fn from_rules(rules: Vec<Rule>) -> Result<Self, ValidatronError> {
        let compiled_rules = rules
            .into_iter()
            .map(Rule::compile)
            .collect::<Result<Vec<_>, ValidatronError>>()?;

        log::debug!("Loaded {} rules", compiled_rules.len());

        Ok(Self {
            rules: compiled_rules,
        })
    }

    /// Perform the check on an instance of a type `T` and returns an iterator over the matching rules.
    pub fn matches<'a, 'b>(&'a self, e: &'b T) -> impl Iterator<Item = &'b CompiledRule<T>>
    where
        'a: 'b,
    {
        self.rules.iter().filter(|rule| rule.is_match(e))
    }
}

#[derive(Debug, Clone, Validatron)]
pub struct MyStruct {
    pub a: i32,
    pub b: i32,
}

fn main() {
    let rules = vec![
        Rule {
            name: "A > 0".to_string(),
            condition: validatron::Condition::Binary {
                l: vec![Identifier::Field(validatron::Field::Simple(SimpleField(
                    "a".to_string(),
                )))],
                op: Operator::Relational(RelationalOperator::Greater),
                r: validatron::RValue::Value("0".to_string()),
            },
        },
        Rule {
            name: "B > 0".to_string(),
            condition: validatron::Condition::Binary {
                l: vec![Identifier::Field(validatron::Field::Simple(SimpleField(
                    "b".to_string(),
                )))],
                op: Operator::Relational(RelationalOperator::Greater),
                r: validatron::RValue::Value("0".to_string()),
            },
        },
    ];

    let ruleset: Ruleset<MyStruct> = Ruleset::from_rules(rules).unwrap();

    let matches_count = ruleset.matches(&MyStruct { a: 1, b: -1 }).count();

    assert!(matches_count == 1, "matches count not corresponding");
}
