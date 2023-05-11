use std::{
    any::{type_name, Any},
    marker::PhantomData,
};

use crate::{Validatron, ValidatronClass, ValidatronClassKind, ValidatronError};

// The only operator currently supported on collections is MultiOperator::Contains.
//
/// These closure types work over dyn Any to simplify code, but expect to be called with
/// the correct type.
/// For maximum performance, the unchecked version will blindly assume the input type to be correct.
/// When unsure about input correctness, the normal version must be called, which will return None
/// when the input type is wrong.
//
// Check if collection contains const value
type DynContainsFn = Box<dyn for<'c> Fn(&'c dyn Any) -> Option<bool> + Send + Sync>;
type DynContainsFnUnchecked = Box<dyn for<'c> Fn(&'c dyn Any) -> bool + Send + Sync>;
// Check if collection (second argument) contains the first argument
type DynContainsMulti = Box<dyn Fn(&dyn Any, &dyn Any) -> Option<bool> + Send + Sync>;
type DynContainsMultiUnchecked = Box<dyn Fn(&dyn Any, &dyn Any) -> bool + Send + Sync>;

pub struct CollectionClassBuilder(());

impl CollectionClassBuilder {
    pub(crate) fn create_class<T, U>() -> ValidatronClass
    where
        T: Validatron + 'static,
        U: Validatron + 'static,
        for<'x> &'x T: IntoIterator<Item = &'x U>,
    {
        ValidatronClass {
            kind: ValidatronClassKind::Collection(Collection {
                name: type_name::<T>(),
                inner: Box::new(CollectionType::<T, U> {
                    pha: PhantomData,
                    pha2: PhantomData,
                }),
            }),
        }
    }
}

/// Collection type representation.
pub struct Collection {
    name: &'static str,
    inner: Box<dyn CollectionTypeDyn>,
}

impl Collection {
    pub fn get_name(&self) -> &'static str {
        self.name
    }

    pub fn get_value_class(&self) -> ValidatronClass {
        self.inner.get_value_class()
    }

    pub fn contains_fn_any_value(&self, value: &str) -> Result<DynContainsFn, ValidatronError> {
        self.inner.contains_fn_any_value(value)
    }

    /// # Safety
    ///
    /// The `unsafe` is related to the returned function. That function accepts values as [Any],
    /// but must be called with values of the right type, because it doesn't perform checks.
    pub unsafe fn contains_fn_any_value_unchecked(
        &self,
        value: &str,
    ) -> Result<DynContainsFnUnchecked, ValidatronError> {
        self.inner.contains_fn_any_value_unchecked(value)
    }

    pub fn contains_fn_any_multi(&self) -> Result<DynContainsMulti, ValidatronError> {
        self.inner.contains_fn_any_multi()
    }

    /// # Safety
    ///
    /// The `unsafe` is related to the returned function. That function accepts values as [Any],
    /// but must be called with values of the right type, because it doesn't perform checks.
    pub unsafe fn contains_fn_any_multi_unchecked(
        &self,
    ) -> Result<DynContainsMultiUnchecked, ValidatronError> {
        self.inner.contains_fn_any_multi_unchecked()
    }
}

trait CollectionTypeDyn {
    fn get_value_class(&self) -> ValidatronClass;

    fn contains_fn_any_value(&self, value: &str) -> Result<DynContainsFn, ValidatronError>;

    unsafe fn contains_fn_any_value_unchecked(
        &self,
        value: &str,
    ) -> Result<DynContainsFnUnchecked, ValidatronError>;

    fn contains_fn_any_multi(&self) -> Result<DynContainsMulti, ValidatronError>;

    unsafe fn contains_fn_any_multi_unchecked(
        &self,
    ) -> Result<DynContainsMultiUnchecked, ValidatronError>;
}

struct CollectionType<T, U>
where
    T: Validatron + 'static,
    U: Validatron + 'static,
    for<'x> &'x T: IntoIterator<Item = &'x U>,
{
    pha: PhantomData<T>,
    pha2: PhantomData<U>,
}

impl<T, U> CollectionTypeDyn for CollectionType<T, U>
where
    T: Validatron + 'static,
    U: Validatron + 'static,
    for<'x> &'x T: IntoIterator<Item = &'x U>,
{
    fn get_value_class(&self) -> ValidatronClass {
        U::get_class()
    }

    fn contains_fn_any_value(&self, value: &str) -> Result<DynContainsFn, ValidatronError> {
        let ValidatronClassKind::Primitive(primitive) = U::get_class().into_kind() else {
            return Err(ValidatronError::CollectionValueNotPrimitive);
        };

        let cmp = primitive.compare_fn_any_value(
            crate::Operator::Relational(crate::RelationalOperator::Equals),
            value,
        )?;

        Ok(Box::new(move |source| {
            source.downcast_ref::<T>().and_then(|source| {
                for item in source.into_iter() {
                    if cmp(item)? {
                        return Some(true);
                    }
                }
                Some(false)
            })
        }))
    }

    unsafe fn contains_fn_any_value_unchecked(
        &self,
        value: &str,
    ) -> Result<DynContainsFnUnchecked, ValidatronError> {
        let ValidatronClassKind::Primitive(primitive) = U::get_class().into_kind() else {
            return Err(ValidatronError::CollectionValueNotPrimitive);
        };

        let cmp = primitive.compare_fn_any_value_unchecked(
            crate::Operator::Relational(crate::RelationalOperator::Equals),
            value,
        )?;

        Ok(Box::new(move |source| {
            let source = &*(source as *const dyn Any as *const T);

            source.into_iter().any(|item| cmp(item))
        }))
    }

    fn contains_fn_any_multi(&self) -> Result<DynContainsMulti, ValidatronError> {
        let ValidatronClassKind::Primitive(primitive) = U::get_class().into_kind() else {
            return Err(ValidatronError::CollectionValueNotPrimitive);
        };

        let cmp = primitive.compare_fn_any_multi(crate::Operator::Relational(
            crate::RelationalOperator::Equals,
        ))?;

        Ok(Box::new(move |collection, second| {
            collection.downcast_ref::<T>().and_then(|collection| {
                second.downcast_ref::<U>().and_then(|second| {
                    for item in collection.into_iter() {
                        if cmp(item, second)? {
                            return Some(true);
                        }
                    }
                    Some(false)
                })
            })
        }))
    }

    unsafe fn contains_fn_any_multi_unchecked(
        &self,
    ) -> Result<DynContainsMultiUnchecked, ValidatronError> {
        let ValidatronClassKind::Primitive(primitive) = U::get_class().into_kind() else {
            return Err(ValidatronError::CollectionValueNotPrimitive);
        };

        let cmp = primitive.compare_fn_any_multi_unchecked(crate::Operator::Relational(
            crate::RelationalOperator::Equals,
        ))?;

        Ok(Box::new(move |collection, second| {
            let collection = &*(collection as *const dyn Any as *const T);
            let second = &*(second as *const dyn Any as *const U);

            collection.into_iter().any(|item| cmp(item, second))
        }))
    }
}
