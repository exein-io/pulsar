use std::{
    any::{type_name, Any},
    collections::HashMap,
    marker::PhantomData,
};

use super::methods::Method0CallFn;
use crate::{MethodsBuilder, Validatron, ValidatronClass, ValidatronClassKind};

// Extractor closure which gets an object of type F from an enum of type T.
// Could return None if the enum is of the wrong variant.
type EnumFieldExtractorFn<T, F> = Box<dyn Fn(&T) -> Option<&F> + Send + Sync>;

// Closures to extract a field from an enum.
// These closure types work over dyn Any to simplify code, but expect to be called with
// the correct type.
// For maximum performance, the unchecked version will blindly assume the input type to be correct.
// When unsure about input correctness, the normal version must be called, which will return None
// when the input type is wrong.
// Since the input could be of a variant which doesn't contain the value to extract,
// all these closure could return None.
type DynEnumFieldExtractorFn = Box<dyn (Fn(&dyn Any) -> Option<Option<&dyn Any>>) + Send + Sync>;
type UncheckedDynEnumFieldExtractorFn = Box<dyn (Fn(&dyn Any) -> Option<&dyn Any>) + Send + Sync>;

pub struct EnumClassBuilder<T> {
    name: &'static str,
    variants: HashMap<&'static str, HashMap<&'static str, VariantAttribute>>,
    methods_builder: MethodsBuilder<T>,
    _phantom: PhantomData<T>,
}

impl<T: Validatron + 'static> EnumClassBuilder<T> {
    pub(super) fn new() -> Self {
        Self {
            name: type_name::<T>(),
            variants: HashMap::new(),
            _phantom: PhantomData,
            methods_builder: MethodsBuilder::new(),
        }
    }

    // TODO: decide if implment a parametric variant: can be parametric
    // over access_function but costs size due to monomorphization T*F,
    // but cost should be minimal because of the body of the function
    /// Insert a field into the variant definition.
    pub fn add_variant_field<F: Validatron + 'static>(
        mut self,
        variant_name: &'static str,
        field_name: &'static str,
        access_fn: EnumFieldExtractorFn<T, F>,
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

    pub fn add_method0<F: Validatron + 'static>(
        mut self,
        name: &'static str,
        execute_fn: Method0CallFn<T, F>,
    ) -> Self {
        self.methods_builder = self.methods_builder.add_method0(name, execute_fn);

        self
    }

    /// Finalize the enum class.
    pub fn build(self) -> ValidatronClass {
        ValidatronClass {
            kind: ValidatronClassKind::Enum(Enum {
                name: self.name,
                variants: self.variants,
            }),
            methods: self.methods_builder.build(),
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
        .or_default()
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

    pub fn into_extractor_fn(self) -> DynEnumFieldExtractorFn {
        self.inner.into_extractor_fn()
    }

    /// # Safety
    ///
    /// The `unsafe` is related to the returned function. That function accepts values as [Any],
    /// but must be called with values of the right type, because it doesn't perform checks.
    pub unsafe fn into_extractor_fn_unchecked(self) -> UncheckedDynEnumFieldExtractorFn {
        self.inner.into_extractor_fn_unchecked()
    }
}

trait VariantAttributeTypeDyn {
    fn get_class(&self) -> ValidatronClass;

    fn into_extractor_fn(self: Box<Self>) -> DynEnumFieldExtractorFn;

    unsafe fn into_extractor_fn_unchecked(self: Box<Self>) -> UncheckedDynEnumFieldExtractorFn;
}

struct VariantAttributeType<T, F>
where
    T: Validatron,
    F: Validatron,
{
    extractor: EnumFieldExtractorFn<T, F>,
}

impl<T, F> VariantAttributeTypeDyn for VariantAttributeType<T, F>
where
    T: Validatron + 'static,
    F: Validatron + 'static,
{
    fn get_class(&self) -> ValidatronClass {
        F::get_class()
    }

    fn into_extractor_fn(self: Box<Self>) -> DynEnumFieldExtractorFn {
        Box::new(move |source| {
            source
                .downcast_ref()
                .map(|source| (self.extractor)(source).map(|res| res as _))
        })
    }

    unsafe fn into_extractor_fn_unchecked(self: Box<Self>) -> UncheckedDynEnumFieldExtractorFn {
        Box::new(move |source| {
            let source = &*(source as *const dyn Any as *const T);

            (self.extractor)(source).map(|res| res as _)
        })
    }
}
