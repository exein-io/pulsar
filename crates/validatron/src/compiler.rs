use crate::{validator, Condition, Validatron, ValidatronError};

/// Final form of a rule for a type `T`.
///
/// It possible to apply the rule on a reference of `T` to see it it matches.
pub struct CompiledRule<T: Validatron + 'static> {
    pub name: String,
    pub condition: CompiledCondition<T>,
}

impl<T: Validatron> CompiledRule<T> {
    pub fn is_match(&self, e: &T) -> bool {
        (self.condition.0)(e)
    }
}

/// It contains the logic of a rule for a given type `T`.
///
/// It an abstraction of a function that takes a reference of type `T` and returns a [bool].
///
/// Its content is a closure generated with the [compile_condition] function
pub struct CompiledCondition<T>(pub(crate) Box<dyn Fn(&T) -> bool + Send + Sync>);

/// Entrypoint to validate a condition for a given type `T`.
///
/// In case of success returns a [ValidatedCondition] for the given type `T`.
pub fn validate_condition<T: Validatron + 'static>(
    condition: Condition,
) -> Result<ValidatedCondition<T>, ValidatronError> {
    match condition {
        Condition::And { l, r } => {
            let l = validate_condition(*l)?;
            let r = validate_condition(*r)?;

            Ok(ValidatedCondition::And {
                l: Box::new(l),
                r: Box::new(r),
            })
        }
        Condition::Or { l, r } => {
            let l = validate_condition(*l)?;
            let r = validate_condition(*r)?;

            Ok(ValidatedCondition::Or {
                l: Box::new(l),
                r: Box::new(r),
            })
        }

        Condition::Not { inner } => {
            let vc = validate_condition(*inner)?;
            Ok(ValidatedCondition::Not {
                inner: Box::new(vc),
            })
        }
        Condition::Base {
            field_path,
            op,
            value,
        } => {
            let validated_field_fn = validator::get_valid_rule::<T>(field_path, op, value)?;

            Ok(ValidatedCondition::Base {
                inner: validated_field_fn.rule_fn,
            })
        }
    }
}

/// Representation of a valid rule for a type `T`.
///
/// Implemented as a tree of [ValidatedCondition::Base] connected with logical operators.
/// The base type contains a functions that takes a reference to `T` and returns a [bool].
pub enum ValidatedCondition<T> {
    And {
        l: Box<ValidatedCondition<T>>,
        r: Box<ValidatedCondition<T>>,
    },
    Or {
        l: Box<ValidatedCondition<T>>,
        r: Box<ValidatedCondition<T>>,
    },
    Not {
        inner: Box<ValidatedCondition<T>>,
    },
    Base {
        inner: Box<dyn Fn(&T) -> bool + Send + Sync>,
    },
}

/// Compiler entrypoint.
///
/// It compiles a tree of [ValidatedCondition] into single [CompiledCondition] object.
///
/// It walks into the tree and recursively generates closures to its leaves returning a single
/// closures encapsulated in a [CompiledCondition] object.
pub fn compile_condition<T: 'static>(c: ValidatedCondition<T>) -> CompiledCondition<T> {
    CompiledCondition(generate_closures(c))
}

/// Recursively generates closures for a [ValidatedCondition] tree of a type `T`.
///
/// Returns a new closure with all the logic of inside.
fn generate_closures<T: 'static>(
    c: ValidatedCondition<T>,
) -> Box<dyn Fn(&T) -> bool + Send + Sync> {
    match c {
        ValidatedCondition::And { l, r } => {
            let l = generate_closures(*l);
            let r = generate_closures(*r);
            Box::new(move |x: &T| (l)(x) && (r)(x))
        }
        ValidatedCondition::Or { l, r } => {
            let l = generate_closures(*l);
            let r = generate_closures(*r);
            Box::new(move |x: &T| (l)(x) || (r)(x))
        }
        ValidatedCondition::Not { inner } => {
            let c = generate_closures(*inner);
            Box::new(move |x: &T| !(c)(x))
        }
        ValidatedCondition::Base { inner } => inner,
    }
}
