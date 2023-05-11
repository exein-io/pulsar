use crate::{compiler::CompiledRule, Rule, Validatron, ValidatronError};

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
    pub fn matches<'a>(&'a self, e: &'a T) -> impl Iterator<Item = &CompiledRule<T>> {
        self.rules.iter().filter(|rule| rule.is_match(e))
    }
}
