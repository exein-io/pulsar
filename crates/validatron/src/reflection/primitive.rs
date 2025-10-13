use std::any::{Any, TypeId, type_name};

use crate::{
    HandleOperatorFn, MethodsBuilder, Operator, Validatron, ValidatronClass, ValidatronClassKind,
    ValidatronError,
};

// These closure are variations over OperatorFn<T>, since they all
// implementat a particular operator over two values.
//
// There's callback definitions for:
// - normal operators (Multi suffix): apply the given operator over the two input T and return bool
// - constant operators (Mono suffix): take only one T as input and compares it the a constant value
//
// They all work over dyn Any to simplify code, but expect the input to be correct.
// Because of this, we have two versions of each:
// - a normal version which returns None if the input is invalid
// - an unchecked version which just assumes the input to be valid. The caller
//   MUST make sure to uphold this invariant.
type DynOperatorMulti = Box<dyn Fn(&dyn Any, &dyn Any) -> Option<bool> + Send + Sync + 'static>;
type DynOperatorMultiUnchecked = Box<dyn Fn(&dyn Any, &dyn Any) -> bool + Send + Sync + 'static>;
type DynOperatorConst = Box<dyn Fn(&dyn Any) -> Option<bool> + Send + Sync + 'static>;
type DynOperatorConstUnchecked = Box<dyn Fn(&dyn Any) -> bool + Send + Sync + 'static>;

/// Value parsing function: given a string, try to parse T;
pub type ParseFn<T> = Box<dyn Fn(&str) -> Result<T, ValidatronError> + Send + Sync + 'static>;

/// Primitive class builder
pub struct PrimitiveClassBuilder<T> {
    parse_fn: ParseFn<T>,
    handle_op_fn: HandleOperatorFn<T>,
    method_builder: MethodsBuilder<T>,
}

impl<T: Validatron + Sync + Send + 'static> PrimitiveClassBuilder<T> {
    pub(super) fn new(parse_fn: ParseFn<T>, handle_op_fn: HandleOperatorFn<T>) -> Self {
        Self {
            parse_fn,
            handle_op_fn,
            method_builder: MethodsBuilder::new(),
        }
    }

    pub fn build(self) -> ValidatronClass {
        ValidatronClass {
            kind: ValidatronClassKind::Primitive(Primitive::new(self.parse_fn, self.handle_op_fn)),
            methods: self.method_builder.build(),
        }
    }
}

/// Primitive type representation.
pub struct Primitive {
    name: &'static str,
    inner: Box<dyn PrimitiveTypeDyn>,
}

impl Primitive {
    pub(super) fn new<T: Validatron + Send + Sync + 'static>(
        parse_fn: ParseFn<T>,
        handle_op_fn: HandleOperatorFn<T>,
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
    ) -> Result<DynOperatorConst, ValidatronError> {
        self.inner.compare_fn_any_value(op, value)
    }

    /// # Safety
    ///
    /// The `unsafe` is related to the returned function. That function accepts values as [Any],
    /// but must be called with values of the right type, because it doesn't perform checks.
    pub unsafe fn compare_fn_any_value_unchecked(
        &self,
        op: Operator,
        value: &str,
    ) -> Result<DynOperatorConstUnchecked, ValidatronError> {
        unsafe { self.inner.compare_fn_any_value_unchecked(op, value) }
    }

    pub fn compare_fn_any_multi(&self, op: Operator) -> Result<DynOperatorMulti, ValidatronError> {
        self.inner.compare_fn_any_multi(op)
    }

    /// # Safety
    ///
    /// The `unsafe` is related to the returned function. That function accepts values as [Any],
    /// but must be called with values of the right type, because it doesn't perform checks.
    pub unsafe fn compare_fn_any_multi_unchecked(
        &self,
        op: Operator,
    ) -> Result<DynOperatorMultiUnchecked, ValidatronError> {
        unsafe { self.inner.compare_fn_any_multi_unchecked(op) }
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
    ) -> Result<DynOperatorConst, ValidatronError>;

    unsafe fn compare_fn_any_value_unchecked(
        &self,
        op: Operator,
        value: &str,
    ) -> Result<DynOperatorConstUnchecked, ValidatronError>;

    fn compare_fn_any_multi(&self, op: Operator) -> Result<DynOperatorMulti, ValidatronError>;

    unsafe fn compare_fn_any_multi_unchecked(
        &self,
        op: Operator,
    ) -> Result<DynOperatorMultiUnchecked, ValidatronError>;

    fn field_type_id(&self) -> TypeId;
}

struct PrimitiveType<T> {
    parse_fn: ParseFn<T>,
    handle_op_fn: HandleOperatorFn<T>,
}

impl<T> PrimitiveTypeDyn for PrimitiveType<T>
where
    T: Send + Sync + 'static,
{
    fn compare_fn_any_value(
        &self,
        op: Operator,
        value: &str,
    ) -> Result<DynOperatorConst, ValidatronError> {
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
    ) -> Result<DynOperatorConstUnchecked, ValidatronError> {
        let value = (self.parse_fn)(value)?;

        let compare_fn = (self.handle_op_fn)(op)?;

        Ok(Box::new(move |source| {
            let source = unsafe { &*(source as *const dyn Any as *const T) };
            compare_fn(source, &value)
        }))
    }

    fn compare_fn_any_multi(&self, op: Operator) -> Result<DynOperatorMulti, ValidatronError> {
        let compare_fn = (self.handle_op_fn)(op)?;

        Ok(Box::new(move |first, second| {
            if let Some(first) = first.downcast_ref()
                && let Some(second) = second.downcast_ref()
            {
                return Some(compare_fn(first, second));
            }

            None
        }))
    }

    unsafe fn compare_fn_any_multi_unchecked(
        &self,
        op: Operator,
    ) -> Result<DynOperatorMultiUnchecked, ValidatronError> {
        let compare_fn = (self.handle_op_fn)(op)?;

        Ok(Box::new(move |first, second| {
            let first = unsafe { &*(first as *const dyn Any as *const T) };
            let second = unsafe { &*(second as *const dyn Any as *const T) };

            compare_fn(first, second)
        }))
    }

    fn field_type_id(&self) -> TypeId {
        TypeId::of::<T>()
    }
}
