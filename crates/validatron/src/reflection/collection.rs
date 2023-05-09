use std::{
    any::{type_name, Any},
    marker::PhantomData,
};

use crate::{Validatron, ValidatronClass, ValidatronClassKind, ValidatronError};

pub struct CollectionClassBuilder(());

impl CollectionClassBuilder {
    pub(crate) fn new<T, U>() -> ValidatronClass
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

    pub fn contains_fn_any_value(
        &self,
        value: &str,
    ) -> Result<Box<dyn for<'c> Fn(&'c dyn Any) -> Option<bool> + Send + Sync>, ValidatronError>
    {
        self.inner.contains_fn_any_value(value)
    }

    pub unsafe fn contains_fn_any_value_unchecked(
        &self,
        value: &str,
    ) -> Result<Box<dyn for<'c> Fn(&'c dyn Any) -> bool + Send + Sync>, ValidatronError> {
        self.inner.contains_fn_any_value_unchecked(value)
    }

    pub fn contains_fn_any_multi(
        &self,
    ) -> Result<Box<dyn Fn(&dyn Any, &dyn Any) -> Option<bool> + Send + Sync>, ValidatronError>
    {
        self.inner.contains_fn_any_multi()
    }

    pub unsafe fn contains_fn_any_multi_unchecked(
        &self,
    ) -> Result<Box<dyn Fn(&dyn Any, &dyn Any) -> bool + Send + Sync>, ValidatronError> {
        self.inner.contains_fn_any_multi_unchecked()
    }
}

trait CollectionTypeDyn {
    fn get_value_class(&self) -> ValidatronClass;

    fn contains_fn_any_value(
        &self,
        value: &str,
    ) -> Result<Box<dyn for<'c> Fn(&'c dyn Any) -> Option<bool> + Send + Sync>, ValidatronError>;

    unsafe fn contains_fn_any_value_unchecked(
        &self,
        value: &str,
    ) -> Result<Box<dyn for<'c> Fn(&'c dyn Any) -> bool + Send + Sync>, ValidatronError>;

    fn contains_fn_any_multi(
        &self,
    ) -> Result<Box<dyn Fn(&dyn Any, &dyn Any) -> Option<bool> + Send + Sync>, ValidatronError>;

    unsafe fn contains_fn_any_multi_unchecked(
        &self,
    ) -> Result<Box<dyn Fn(&dyn Any, &dyn Any) -> bool + Send + Sync>, ValidatronError>;
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

    fn contains_fn_any_value(
        &self,
        value: &str,
    ) -> Result<Box<dyn for<'c> Fn(&'c dyn Any) -> Option<bool> + Send + Sync>, ValidatronError>
    {
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
    ) -> Result<Box<dyn for<'c> Fn(&'c dyn Any) -> bool + Send + Sync>, ValidatronError> {
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

    fn contains_fn_any_multi(
        &self,
    ) -> Result<Box<dyn Fn(&dyn Any, &dyn Any) -> Option<bool> + Send + Sync>, ValidatronError>
    {
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
    ) -> Result<Box<dyn Fn(&dyn Any, &dyn Any) -> bool + Send + Sync>, ValidatronError> {
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
