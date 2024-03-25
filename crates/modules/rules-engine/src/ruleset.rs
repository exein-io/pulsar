use validatron::{CompiledRule, Validatron, ValidatronError};

use crate::engine::{Metadata, RuleWithMetadata};

/// Set of rules which can be applied over any instance of type `T`.
///
/// Each rule has been validated and compiled into single closure.
pub struct Ruleset<T: Validatron + 'static> {
    pub(crate) rules: Vec<CompiledRuleWithMetadata<T>>,
}

/// CompiledRuleWithMetadata is a CompiledRule with additional metadata
/// that is used to store the rule name and description.
pub struct CompiledRuleWithMetadata<T: Validatron + 'static> {
    pub rule: CompiledRule<T>,
    pub metadata: Metadata,
}

impl<T: Validatron> Ruleset<T> {
    /// Create a ruleset from a [Vec] of [CompiledRuleWithMetadata].
    #[allow(dead_code)]
    pub fn from_compiled(rules: Vec<CompiledRuleWithMetadata<T>>) -> Self {
        Self { rules }
    }

    /// Try to create a ruleset from a [Vec] of [RuleWithMetadata].
    ///
    /// The rules will be validated and compiled to an optimized form.
    pub fn from_rules(rules: Vec<RuleWithMetadata>) -> Result<Self, ValidatronError> {
        let compiled_rules = rules
            .into_iter()
            .map(|r| {
                r.rule.compile().map(|rule| CompiledRuleWithMetadata {
                    rule,
                    metadata: r.metadata,
                })
            })
            .collect::<Result<Vec<_>, ValidatronError>>()?;

        log::debug!("Loaded {} rules", compiled_rules.len());

        Ok(Self {
            rules: compiled_rules,
        })
    }

    /// Perform the check on an instance of a type `T` and returns an iterator over the matching rules.
    pub fn matches<'a>(&'a self, e: &'a T) -> impl Iterator<Item = &CompiledRuleWithMetadata<T>> {
        self.rules.iter().filter(|r| r.rule.is_match(e))
    }
}
