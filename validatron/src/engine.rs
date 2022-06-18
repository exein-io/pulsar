use std::collections::HashMap;

use crate::{
    compiler::{compile_condition, validate_condition, CompiledRule},
    Rule, ValidatedCondition, ValidatronError, ValidatronVariant,
};

pub struct Engine<T: ValidatronVariant + 'static>(pub(crate) HashMap<usize, Vec<CompiledRule<T>>>);

impl<T: ValidatronVariant> Engine<T> {
    pub fn from_compiled(rules: HashMap<usize, Vec<CompiledRule<T>>>) -> Self {
        Self(rules)
    }

    pub fn from_rules(rules: Vec<Rule>) -> Result<Self, ValidatronError> {
        let validated_conditions = rules
            .into_iter()
            .map(|rule| {
                validate_condition(rule.condition, &rule.typ)
                    .map(|(var_num, validated)| (rule.name, var_num, validated))
            })
            .collect::<Result<Vec<(String, usize, ValidatedCondition<T>)>, ValidatronError>>()?;

        let compiled_conditions: Vec<(usize, CompiledRule<T>)> = validated_conditions
            .into_iter()
            .map(|(name, var_num, c)| {
                (
                    var_num,
                    CompiledRule {
                        name,
                        condition: compile_condition(c),
                    },
                )
            })
            .collect();

        log::debug!("Loaded {} rules", compiled_conditions.len());

        let mut by_variant = HashMap::new();

        for (variant_num, c) in compiled_conditions {
            by_variant.entry(variant_num).or_insert(Vec::new()).push(c);
        }

        Ok(Self(by_variant))
    }

    pub fn run<F: Fn(&CompiledRule<T>)>(&self, e: &T, cb: F) {
        if let Some(rules) = self.0.get(&e.var_num()) {
            for rule in rules {
                if rule.is_match(e) {
                    cb(rule)
                }
            }
        }
    }
}
