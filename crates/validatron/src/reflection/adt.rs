use std::{
    any::{type_name, Any},
    collections::HashMap,
    marker::PhantomData,
};

use crate::{Validatron, ValidatronClass, ValidatronClassKind};

pub struct EnumClassBuilder<T> {
    name: &'static str,
    variants: HashMap<&'static str, HashMap<&'static str, VariantAttribute>>,
    _phantom: PhantomData<T>,
}

impl<T: Validatron + 'static> EnumClassBuilder<T> {
    pub(super) fn new() -> Self {
        Self {
            name: type_name::<T>(),
            variants: HashMap::new(),
            _phantom: PhantomData,
        }
    }

    // TODO: decide if implment a parametric variant: can be parametric over access_function but costs size due to monomorphization T*F,
    // but cost should be minimal because of the body of the function
    /// Insert a field into the variant definition.
    pub fn add_variant_field<F: Validatron + 'static>(
        mut self,
        variant_name: &'static str,
        field_name: &'static str,
        access_fn: Box<dyn Fn(&T) -> Option<&F> + Send + Sync>,
    ) -> Self {
        let variant_attribute_type = VariantAttributeType::<T, F> {
            extractor: access_fn,
        };
        let variant = VariantAttribute {
            variant_name,
            field_name,
            parent_enum_name: self.name,
            inner: Box::new(variant_attribute_type),
        };

        add_variant(&mut self.variants, variant_name, field_name, variant);

        self
    }

    /// Finalize the enum class.
    pub fn build(self) -> ValidatronClass {
        ValidatronClass {
            kind: ValidatronClassKind::Enum(Enum {
                name: self.name,
                variants: self.variants,
            }),
        }
    }
}

// no monomorphization helper
fn add_variant(
    fields_map: &mut HashMap<&'static str, HashMap<&'static str, VariantAttribute>>,
    variant_name: &'static str,
    field_name: &'static str,
    variant: VariantAttribute,
) {
    if fields_map
        .entry(variant_name)
        .or_insert(HashMap::new())
        .insert(field_name, variant)
        .is_some()
    {
        panic!("you added two variant+field with the same name '{variant_name}+{field_name}' into a enum class definition")
    }
}

/// Enum type representation.
pub struct Enum {
    name: &'static str,
    variants: HashMap<&'static str, HashMap<&'static str, VariantAttribute>>,
}

impl Enum {
    pub fn get_name(&self) -> &'static str {
        self.name
    }

    pub fn get_variant_field(
        &self,
        variant_name: &str,
        field_name: &str,
    ) -> Option<&VariantAttribute> {
        self.variants
            .get(variant_name)
            .and_then(|field_map| field_map.get(field_name))
    }

    pub fn get_variant_field_owned(
        mut self,
        variant_name: &str,
        field_name: &str,
    ) -> Option<VariantAttribute> {
        self.variants
            .remove(variant_name)
            .and_then(|mut field_map| field_map.remove(field_name))
    }
}

/// Enum attribute representation.
pub struct VariantAttribute {
    variant_name: &'static str,
    field_name: &'static str,
    parent_enum_name: &'static str,
    inner: Box<dyn VariantAttributeTypeDyn>,
}

impl VariantAttribute {
    pub fn get_variant_name(&self) -> &'static str {
        self.variant_name
    }

    pub fn get_field_name(&self) -> &'static str {
        self.field_name
    }

    pub fn get_parent_enum_name(&self) -> &'static str {
        self.parent_enum_name
    }

    pub fn get_class(&self) -> ValidatronClass {
        self.inner.get_class()
    }

    pub fn into_extractor_fn(
        self,
    ) -> Box<dyn (Fn(&dyn Any) -> Option<Option<&dyn Any>>) + Send + Sync> {
        self.inner.into_extractor_fn()
    }

    /// # Safety
    ///
    /// The `unsafe` is related to the returned function. That function accepts values as [Any],
    /// but must be called with values of the right type, because it doesn't perform checks.
    pub unsafe fn into_extractor_fn_unchecked(
        self,
    ) -> Box<dyn (Fn(&dyn Any) -> Option<&dyn Any>) + Send + Sync> {
        self.inner.into_extractor_fn_unchecked()
    }
}

trait VariantAttributeTypeDyn {
    fn get_class(&self) -> ValidatronClass;

    fn into_extractor_fn(
        self: Box<Self>,
    ) -> Box<dyn (Fn(&dyn Any) -> Option<Option<&dyn Any>>) + Send + Sync>;

    unsafe fn into_extractor_fn_unchecked(
        self: Box<Self>,
    ) -> Box<dyn Fn(&dyn Any) -> Option<&dyn Any> + Send + Sync>;
}

struct VariantAttributeType<T, U>
where
    T: Validatron,
    U: Validatron,
{
    extractor: Box<dyn Fn(&T) -> Option<&U> + Send + Sync>,
}

impl<T, U> VariantAttributeTypeDyn for VariantAttributeType<T, U>
where
    T: Validatron + 'static,
    U: Validatron + 'static,
{
    fn get_class(&self) -> ValidatronClass {
        U::get_class()
    }

    fn into_extractor_fn(
        self: Box<Self>,
    ) -> Box<dyn (Fn(&dyn Any) -> Option<Option<&dyn Any>>) + Send + Sync> {
        Box::new(move |source| {
            source
                .downcast_ref()
                .map(|source| (self.extractor)(source).map(|res| res as _))
        })
    }

    unsafe fn into_extractor_fn_unchecked(
        self: Box<Self>,
    ) -> Box<dyn Fn(&dyn Any) -> Option<&dyn Any> + Send + Sync> {
        Box::new(move |source| {
            let source = &*(source as *const dyn Any as *const T);

            (self.extractor)(source).map(|res| res as _)
        })
    }
}
