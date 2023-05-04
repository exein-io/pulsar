use crate::{validator, Condition, Validatron, ValidatronError};

pub struct CompiledRule<T: Validatron + 'static> {
    pub name: String,
    pub condition: CompiledCondition<T>,
}

impl<T: Validatron> CompiledRule<T> {
    pub fn is_match(&self, e: &T) -> bool {
        (self.condition.0)(e)
    }
}

pub struct CompiledCondition<T>(pub(crate) Box<dyn Fn(&T) -> bool + Send + Sync>);

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

pub fn compile_condition<T: 'static>(c: ValidatedCondition<T>) -> CompiledCondition<T> {
    CompiledCondition(generate_closures(c))
}

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
