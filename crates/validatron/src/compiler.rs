use crate::{parser, ValidatronError, ValidatronVariant};

pub struct CompiledRule<T: ValidatronVariant + 'static> {
    pub name: String,
    pub condition: CompiledCondition<T>,
}

impl<T: ValidatronVariant> CompiledRule<T> {
    pub fn is_match(&self, e: &T) -> bool {
        (self.condition.0)(e)
    }
}

pub struct CompiledCondition<T>(pub(crate) Box<dyn Fn(&T) -> bool + Send + Sync>);

pub fn validate_condition<T: ValidatronVariant>(
    condition: parser::Condition,
    variant: &str,
) -> Result<(usize, ValidatedCondition<T>), ValidatronError> {
    match condition {
        parser::Condition::And { l, r } => {
            let (ul, l) = validate_condition(*l, variant)?;
            let (ur, r) = validate_condition(*r, variant)?;
            assert_eq!(ul, ur);
            Ok((
                ul,
                ValidatedCondition::And {
                    l: Box::new(l),
                    r: Box::new(r),
                },
            ))
        }
        parser::Condition::Or { l, r } => {
            let (ul, l) = validate_condition(*l, variant)?;
            let (ur, r) = validate_condition(*r, variant)?;
            assert_eq!(ul, ur);
            Ok((
                ul,
                ValidatedCondition::Or {
                    l: Box::new(l),
                    r: Box::new(r),
                },
            ))
        }

        parser::Condition::Not { inner } => {
            let (u, vc) = validate_condition(*inner, variant)?;
            Ok((
                u,
                ValidatedCondition::Not {
                    inner: Box::new(vc),
                },
            ))
        }
        parser::Condition::Base { field, op, value } => {
            let (var_num, validated_field_fn) =
                ValidatronVariant::validate(variant, &field, op, &value)?;
            Ok((
                var_num,
                ValidatedCondition::Base {
                    inner: validated_field_fn,
                },
            ))
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
