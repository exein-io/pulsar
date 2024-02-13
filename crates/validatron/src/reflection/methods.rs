use std::{
    any::{type_name, Any},
    collections::HashMap,
    marker::PhantomData,
};

use crate::{Validatron, ValidatronClass};

// Extractor closure which gets an object of type F from an object of type T
pub(super) type Method0CallFn<T, F> = Box<dyn Fn(&T) -> F + Send + Sync>;

// Closures to extract a field from a struct object.
// These closure types work over dyn Any to simplify code, but expect to be called with
// the correct type.
// For maximum performance, the unchecked version will blindly assume the input type to be correct.
// When unsure about input correctness, the normal version must be called, which will return None
// when the input type is wrong.
type DynMethod0CallFn = Box<dyn (Fn(&dyn Any) -> Option<Box<dyn Any>>) + Send + Sync>;
type UncheckedDynMethod0CallFn = Box<dyn (Fn(&dyn Any) -> Box<dyn Any>) + Send + Sync>;

pub struct MethodsBuilder<T> {
    class_name: &'static str,
    methods: HashMap<&'static str, Method>,
    _phantom: PhantomData<T>,
}

impl<T: Validatron + 'static> MethodsBuilder<T> {
    pub(super) fn new() -> Self {
        Self {
            class_name: type_name::<T>(),
            methods: HashMap::new(),
            _phantom: PhantomData,
        }
    }

    // TODO: decide if implement a parametric variant: can be parametric
    // over access_function but costs size due to monomorphization T*F,
    // but cost should be minimal because of the body of the function
    /// Insert a field into the struct definition.
    pub fn add_method0<F: Validatron + 'static>(
        mut self,
        name: &'static str,
        execute_fn: Method0CallFn<T, F>,
    ) -> Self {
        let method_type = MethodType0::<T, F> {
            executor: execute_fn,
        };

        let attribute = Method {
            name,
            parent_class_name: self.class_name,
            inner: Box::new(method_type),
        };

        add_method(&mut self.methods, name, attribute);

        self
    }

    pub(crate) fn build(self) -> Methods {
        Methods {
            name: self.class_name,
            methods: self.methods,
        }
    }
}

// no monomorphization helper
fn add_method(
    methods_map: &mut HashMap<&'static str, Method>,
    name: &'static str,
    attribute: Method,
) {
    if methods_map.insert(name, attribute).is_some() {
        panic!("you added two field with the same name '{name}' into a struct class definition")
    }
}

/// Methods type representation.
pub struct Methods {
    name: &'static str,
    methods: HashMap<&'static str, Method>,
}

impl Methods {
    pub fn get_name(&self) -> &'static str {
        self.name
    }

    pub fn get_method(&self, field_name: &str) -> Option<&Method> {
        self.methods.get(field_name)
    }

    pub fn get_method_owned(mut self, field_name: &str) -> Option<Method> {
        self.methods.remove(field_name)
    }
}

/// Method type representation.
pub struct Method {
    name: &'static str,
    parent_class_name: &'static str,
    inner: Box<dyn MethodTypeDyn>,
}

impl Method {
    pub fn get_name(&self) -> &'static str {
        self.name
    }

    pub fn get_parent_class_name(&self) -> &'static str {
        self.parent_class_name
    }

    pub fn get_class(&self) -> ValidatronClass {
        self.inner.get_class()
    }

    pub fn into_extractor_fn(self) -> DynMethod0CallFn {
        self.inner.into_extractor_fn()
    }

    /// # Safety
    ///
    /// The `unsafe` is related to the returned function. That function accepts values as [Any],
    /// but must be called with values of the right type, because it doesn't perform checks.
    pub unsafe fn into_extractor_fn_unchecked(self) -> UncheckedDynMethod0CallFn {
        self.inner.into_extractor_fn_unchecked()
    }
}

trait MethodTypeDyn {
    fn get_class(&self) -> ValidatronClass;

    fn into_extractor_fn(self: Box<Self>) -> DynMethod0CallFn;

    unsafe fn into_extractor_fn_unchecked(self: Box<Self>) -> UncheckedDynMethod0CallFn;
}

struct MethodType0<T, F>
where
    T: Validatron,
    F: Validatron,
{
    executor: Box<dyn Fn(&T) -> F + Send + Sync>,
}

impl<T, F> MethodTypeDyn for MethodType0<T, F>
where
    T: Validatron + 'static,
    F: Validatron + 'static,
{
    fn get_class(&self) -> ValidatronClass {
        F::get_class()
    }

    fn into_extractor_fn(self: Box<Self>) -> DynMethod0CallFn {
        Box::new(move |source| {
            source
                .downcast_ref()
                .map(|source| Box::new((self.executor)(source)) as _)
        })
    }

    unsafe fn into_extractor_fn_unchecked(self: Box<Self>) -> UncheckedDynMethod0CallFn {
        Box::new(move |source| {
            let source = &*(source as *const dyn Any as *const T);

            Box::new((self.executor)(source)) as _
        })
    }
}
