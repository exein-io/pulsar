use std::marker::PhantomData;

mod adt;
mod collection;
mod primitive;
mod structure;

pub use adt::*;
pub use collection::*;
pub use primitive::*;
pub use structure::*;

use crate::{Operator, ValidatronError};

pub trait Validatron: Sized {
    fn class_builder() -> ClassBuilder<Self> {
        ClassBuilder {
            _phantom: PhantomData,
        }
    }
    fn get_class() -> ValidatronClass;
}

impl<T: Validatron> Validatron for &T {
    fn get_class() -> ValidatronClass {
        T::get_class()
    }
}

pub struct ClassBuilder<T> {
    _phantom: PhantomData<T>,
}

impl<T: Validatron + Send + Sync + 'static> ClassBuilder<T> {
    pub fn primitive(
        self,
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
    ) -> ValidatronClass {
        ValidatronClass {
            kind: ValidatronClassKind::Primitive(Primitive::new(parse_fn, handle_op_fn)),
        }
    }

    pub fn struct_class_builder(self) -> StructClassBuilder<T> {
        StructClassBuilder::new()
    }

    pub fn enum_class_builder(self) -> EnumClassBuilder<T> {
        EnumClassBuilder::new()
    }
}

impl<T> ClassBuilder<T>
where
    T: Validatron + 'static,
{
    pub fn collection<U>(self) -> ValidatronClass
    where
        U: Validatron + 'static,
        for<'x> &'x T: IntoIterator<Item = &'x U>,
    {
        CollectionClassBuilder::new::<T, U>()
    }
}

pub struct ValidatronClass {
    kind: ValidatronClassKind,
    // this space is to implement method calls
}

impl ValidatronClass {
    pub fn get_name(&self) -> &'static str {
        match self.kind() {
            ValidatronClassKind::Primitive(p) => p.get_name(),
            ValidatronClassKind::Struct(s) => s.get_name(),
            ValidatronClassKind::Enum(e) => e.get_name(),
            ValidatronClassKind::Collection(c) => c.get_name(),
        }
    }

    pub fn kind(&self) -> &ValidatronClassKind {
        &self.kind
    }

    pub fn into_kind(self) -> ValidatronClassKind {
        self.kind
    }
}

pub enum ValidatronClassKind {
    Primitive(Primitive),
    Struct(Struct),
    Enum(Enum),
    Collection(Collection),
}
