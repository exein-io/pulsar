use std::{
    any::{type_name, Any},
    collections::HashMap,
    marker::PhantomData,
};

use crate::{Validatron, ValidatronClass, ValidatronClassKind};

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

    // TODO: decide if implment a parametric variant: can be parametric over access_function but costs size due to monomorphization T*F,
    // but cost should be minimal because of the body of the function
    /// Insert a field into the struct definition.
    pub fn add_field<F: Validatron + 'static>(
        mut self,
        name: &'static str,
        access_fn: Box<dyn Fn(&T) -> &F + Send + Sync>,
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

    pub fn into_extractor_fn(self) -> Box<dyn (Fn(&dyn Any) -> Option<&dyn Any>) + Send + Sync> {
        self.inner.into_extractor_fn()
    }

    /// # Safety
    ///
    /// The `unsafe` is related to the returned function. That function accepts values as [Any],
    /// but must be called with values of the right type, because it doesn't perform checks.
    pub unsafe fn into_extractor_fn_unchecked(
        self,
    ) -> Box<dyn (Fn(&dyn Any) -> &dyn Any) + Send + Sync> {
        self.inner.into_extractor_fn_unchecked()
    }
}

trait AttributeTypeDyn {
    fn get_class(&self) -> ValidatronClass;

    fn into_extractor_fn(
        self: Box<Self>,
    ) -> Box<dyn (Fn(&dyn Any) -> Option<&dyn Any>) + Send + Sync>;

    unsafe fn into_extractor_fn_unchecked(
        self: Box<Self>,
    ) -> Box<dyn (Fn(&dyn Any) -> &dyn Any) + Send + Sync>;
}

struct AttributeType<T, U>
where
    T: Validatron,
    U: Validatron,
{
    extractor: Box<dyn Fn(&T) -> &U + Send + Sync>,
}

impl<T, U> AttributeTypeDyn for AttributeType<T, U>
where
    T: Validatron + 'static,
    U: Validatron + 'static,
{
    fn get_class(&self) -> ValidatronClass {
        U::get_class()
    }

    fn into_extractor_fn(
        self: Box<Self>,
    ) -> Box<dyn (Fn(&dyn Any) -> Option<&dyn Any>) + Send + Sync> {
        Box::new(move |source| {
            source
                .downcast_ref()
                .map(|source| (self.extractor)(source) as _)
        })
    }

    unsafe fn into_extractor_fn_unchecked(
        self: Box<Self>,
    ) -> Box<dyn (Fn(&dyn Any) -> &dyn Any) + Send + Sync> {
        Box::new(move |source| {
            let source = &*(source as *const dyn Any as *const T);

            (self.extractor)(source)
        })
    }
}
