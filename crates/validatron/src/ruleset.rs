use crate::{
    compiler::{compile_condition, validate_condition, CompiledRule},
    Rule, ValidatedCondition, Validatron, ValidatronError,
};

pub struct Ruleset<T: Validatron + 'static> {
    pub(crate) rules: Vec<CompiledRule<T>>,
}

impl<T: Validatron> Ruleset<T> {
    pub fn from_compiled(rules: Vec<CompiledRule<T>>) -> Self {
        Self { rules }
    }

    pub fn from_rules(rules: Vec<Rule>) -> Result<Self, ValidatronError> {
        let validated_conditions = rules
            .into_iter()
            .map(|rule| validate_condition(rule.condition).map(|validated| (rule.name, validated)))
            .collect::<Result<Vec<(String, ValidatedCondition<T>)>, ValidatronError>>()?;

        let compiled_conditions: Vec<CompiledRule<T>> = validated_conditions
            .into_iter()
            .map(|(name, c)| CompiledRule {
                name,
                condition: compile_condition(c),
            })
            .collect();

        log::debug!("Loaded {} rules", compiled_conditions.len());

        Ok(Self {
            rules: compiled_conditions,
        })
    }

    pub fn run<F: Fn(&CompiledRule<T>)>(&self, e: &T, cb: F) {
        for rule in &self.rules {
            if rule.is_match(e) {
                cb(rule)
            }
        }
    }
}
