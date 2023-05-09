use std::any::{type_name, Any, TypeId};

use crate::{Operator, Validatron, ValidatronError};

/// Primitive type representation.
pub struct Primitive {
    name: &'static str,
    inner: Box<dyn PrimitiveTypeDyn>,
}

impl Primitive {
    pub(super) fn new<T: Validatron + Send + Sync + 'static>(
        parse_fn: Box<dyn Fn(&str) -> Result<T, ValidatronError> + Send + Sync + 'static>,
        handle_op_fn: Box<
            dyn Fn(
                    Operator,
                )
                    -> Result<Box<dyn Fn(&T, &T) -> bool + Send + Sync + 'static>, ValidatronError>
                + Send
                + Sync
                + 'static,
        >,
    ) -> Self {
        Self {
            name: type_name::<T>(),
            inner: Box::new(PrimitiveType {
                parse_fn,
                handle_op_fn,
            }),
        }
    }

    pub fn get_name(&self) -> &'static str {
        self.name
    }

    pub fn compare_fn_any_value(
        &self,
        op: Operator,
        value: &str,
    ) -> Result<Box<dyn Fn(&dyn Any) -> Option<bool> + Send + Sync + 'static>, ValidatronError>
    {
        self.inner.compare_fn_any_value(op, value)
    }

    pub unsafe fn compare_fn_any_value_unchecked(
        &self,
        op: Operator,
        value: &str,
    ) -> Result<Box<dyn Fn(&dyn Any) -> bool + Send + Sync + 'static>, ValidatronError> {
        self.inner.compare_fn_any_value_unchecked(op, value)
    }

    pub fn compare_fn_any_multi(
        &self,
        op: Operator,
    ) -> Result<
        Box<dyn Fn(&dyn Any, &dyn Any) -> Option<bool> + Send + Sync + 'static>,
        ValidatronError,
    > {
        self.inner.compare_fn_any_multi(op)
    }

    pub unsafe fn compare_fn_any_multi_unchecked(
        &self,
        op: Operator,
    ) -> Result<Box<dyn Fn(&dyn Any, &dyn Any) -> bool + Send + Sync + 'static>, ValidatronError>
    {
        self.inner.compare_fn_any_multi_unchecked(op)
    }

    pub fn field_type_id(&self) -> TypeId {
        self.inner.field_type_id()
    }
}

trait PrimitiveTypeDyn {
    fn compare_fn_any_value(
        &self,
        op: Operator,
        value: &str,
    ) -> Result<Box<dyn Fn(&dyn Any) -> Option<bool> + Send + Sync + 'static>, ValidatronError>;

    unsafe fn compare_fn_any_value_unchecked(
        &self,
        op: Operator,
        value: &str,
    ) -> Result<Box<dyn Fn(&dyn Any) -> bool + Send + Sync + 'static>, ValidatronError>;

    fn compare_fn_any_multi(
        &self,
        op: Operator,
    ) -> Result<
        Box<dyn Fn(&dyn Any, &dyn Any) -> Option<bool> + Send + Sync + 'static>,
        ValidatronError,
    >;

    unsafe fn compare_fn_any_multi_unchecked(
        &self,
        op: Operator,
    ) -> Result<Box<dyn Fn(&dyn Any, &dyn Any) -> bool + Send + Sync + 'static>, ValidatronError>;

    fn field_type_id(&self) -> TypeId;
}

struct PrimitiveType<T> {
    parse_fn: Box<dyn Fn(&str) -> Result<T, ValidatronError> + Send + Sync + 'static>,
    handle_op_fn: Box<
        dyn Fn(
                Operator,
            )
                -> Result<Box<dyn Fn(&T, &T) -> bool + Send + Sync + 'static>, ValidatronError>
            + Send
            + Sync
            + 'static,
    >,
}

impl<T> PrimitiveTypeDyn for PrimitiveType<T>
where
    T: Send + Sync + 'static,
{
    fn compare_fn_any_value(
        &self,
        op: Operator,
        value: &str,
    ) -> Result<Box<dyn Fn(&dyn Any) -> Option<bool> + Send + Sync + 'static>, ValidatronError>
    {
        let value = (self.parse_fn)(value)?;

        let compare_fn = (self.handle_op_fn)(op)?;

        Ok(Box::new(move |source| {
            source
                .downcast_ref()
                .map(|source| compare_fn(source, &value))
        }))
    }

    unsafe fn compare_fn_any_value_unchecked(
        &self,
        op: Operator,
        value: &str,
    ) -> Result<Box<dyn Fn(&dyn Any) -> bool + Send + Sync + 'static>, ValidatronError> {
        let value = (self.parse_fn)(value)?;

        let compare_fn = (self.handle_op_fn)(op)?;

        Ok(Box::new(move |source| {
            let source = &*(source as *const dyn Any as *const T);
            compare_fn(source, &value)
        }))
    }

    fn compare_fn_any_multi(
        &self,
        op: Operator,
    ) -> Result<
        Box<dyn Fn(&dyn Any, &dyn Any) -> Option<bool> + Send + Sync + 'static>,
        ValidatronError,
    > {
        let compare_fn = (self.handle_op_fn)(op)?;

        Ok(Box::new(move |first, second| {
            if let Some(first) = first.downcast_ref() {
                if let Some(second) = second.downcast_ref() {
                    return Some(compare_fn(first, second));
                }
            }

            None
        }))
    }

    unsafe fn compare_fn_any_multi_unchecked(
        &self,
        op: Operator,
    ) -> Result<Box<dyn Fn(&dyn Any, &dyn Any) -> bool + Send + Sync + 'static>, ValidatronError>
    {
        let compare_fn = (self.handle_op_fn)(op)?;

        Ok(Box::new(move |first, second| {
            let first = &*(first as *const dyn Any as *const T);
            let second = &*(second as *const dyn Any as *const T);

            compare_fn(first, second)
        }))
    }

    fn field_type_id(&self) -> TypeId {
        TypeId::of::<T>()
    }
}
