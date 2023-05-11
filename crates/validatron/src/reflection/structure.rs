use std::{
    any::{type_name, Any},
    collections::HashMap,
    marker::PhantomData,
};

use crate::{Validatron, ValidatronClass, ValidatronClassKind};

// Extractor closure which gets an object of type F from an object of type T
type FieldExtractorFn<T, F> = Box<dyn Fn(&T) -> &F + Send + Sync>;

// Closures to extract a field from a struct object.
// These closure types work over dyn Any to simplify code, but expect to be called with
// the correct type.
// For maximum performance, the unchecked version will blindly assume the input type to be correct.
// When unsure about input correctness, the normal version must be called, which will return None
// when the input type is wrong.
type DynFieldExtractorFn = Box<dyn (Fn(&dyn Any) -> Option<&dyn Any>) + Send + Sync>;
type UncheckedDynFieldExtractorFn = Box<dyn (Fn(&dyn Any) -> &dyn Any) + Send + Sync>;

pub struct StructClassBuilder<T> {
    name: &'static str,
    fields: HashMap<&'static str, Attribute>,
    _phantom: PhantomData<T>,
}

impl<T: Validatron + 'static> StructClassBuilder<T> {
    pub(super) fn new() -> Self {
        Self {
            name: type_name::<T>(),
            fields: HashMap::new(),
            _phantom: PhantomData,
        }
    }

    // TODO: decide if implment a parametric variant: can be parametric
    // over access_function but costs size due to monomorphization T*F,
    // but cost should be minimal because of the body of the function
    /// Insert a field into the struct definition.
    pub fn add_field<F: Validatron + 'static>(
        mut self,
        name: &'static str,
        access_fn: FieldExtractorFn<T, F>,
    ) -> Self {
        let attribute_type = AttributeType::<T, F> {
            extractor: access_fn,
        };

        let attribute = Attribute {
            name,
            parent_struct_name: self.name,
            inner: Box::new(attribute_type),
        };

        add_field(&mut self.fields, name, attribute);

        self
    }

    /// Finalize the struct class.
    pub fn build(self) -> ValidatronClass {
        ValidatronClass {
            kind: ValidatronClassKind::Struct(Struct {
                name: self.name,
                fields: self.fields,
            }),
        }
    }
}

// no monomorphization helper
fn add_field(
    fields_map: &mut HashMap<&'static str, Attribute>,
    name: &'static str,
    attribute: Attribute,
) {
    if fields_map.insert(name, attribute).is_some() {
        panic!("you added two field with the same name '{name}' into a struct class definition")
    }
}

/// Struct type representation.
pub struct Struct {
    name: &'static str,
    fields: HashMap<&'static str, Attribute>,
}

impl Struct {
    pub fn get_name(&self) -> &'static str {
        self.name
    }

    pub fn get_field(&self, field_name: &str) -> Option<&Attribute> {
        self.fields.get(field_name)
    }

    pub fn get_field_owned(mut self, field_name: &str) -> Option<Attribute> {
        self.fields.remove(field_name)
    }
}

/// Struct attribute representation.
pub struct Attribute {
    name: &'static str,
    parent_struct_name: &'static str,
    inner: Box<dyn AttributeTypeDyn>,
}

impl Attribute {
    pub fn get_name(&self) -> &'static str {
        self.name
    }

    pub fn get_parent_struct_name(&self) -> &'static str {
        self.parent_struct_name
    }

    pub fn get_class(&self) -> ValidatronClass {
        self.inner.get_class()
    }

    pub fn into_extractor_fn(self) -> DynFieldExtractorFn {
        self.inner.into_extractor_fn()
    }

    /// # Safety
    ///
    /// The `unsafe` is related to the returned function. That function accepts values as [Any],
    /// but must be called with values of the right type, because it doesn't perform checks.
    pub unsafe fn into_extractor_fn_unchecked(self) -> UncheckedDynFieldExtractorFn {
        self.inner.into_extractor_fn_unchecked()
    }
}

trait AttributeTypeDyn {
    fn get_class(&self) -> ValidatronClass;

    fn into_extractor_fn(self: Box<Self>) -> DynFieldExtractorFn;

    unsafe fn into_extractor_fn_unchecked(self: Box<Self>) -> UncheckedDynFieldExtractorFn;
}

struct AttributeType<T, F>
where
    T: Validatron,
    F: Validatron,
{
    extractor: Box<dyn Fn(&T) -> &F + Send + Sync>,
}

impl<T, F> AttributeTypeDyn for AttributeType<T, F>
where
    T: Validatron + 'static,
    F: Validatron + 'static,
{
    fn get_class(&self) -> ValidatronClass {
        F::get_class()
    }

    fn into_extractor_fn(self: Box<Self>) -> DynFieldExtractorFn {
        Box::new(move |source| {
            source
                .downcast_ref()
                .map(|source| (self.extractor)(source) as _)
        })
    }

    unsafe fn into_extractor_fn_unchecked(self: Box<Self>) -> UncheckedDynFieldExtractorFn {
        Box::new(move |source| {
            let source = &*(source as *const dyn Any as *const T);

            (self.extractor)(source)
        })
    }
}
