//! This module contains the core of the library.
//!
//! It's a small reflection system to provide information on types at runtime.
//!
//! Typically it's not needed to directly interact with this layer because the procedural macro does all the job,
//! unless there is the need to create a new [Primitive] type or a [Collection] type.
//!
//! At the core of the system there is the [Validatron] trait. The implementation of this trait consists in
//! implementing the [Validatron::get_class] method. This method demands for a [ValidatronClass] as a return value
//! and the only way to create this type is to use the [ClassBuilder]. The class builder is a per type helper
//! created with the default method [Validatron::class_builder]. In case of a struct:
//!
//! ```
//! use validatron::{Validatron, ValidatronClass};
//!
//! pub struct MyStruct {
//!     pub a: i32,
//!     pub b: i32,
//!     pub c: i32,
//! }
//!
//! impl Validatron for MyStruct {
//!     fn get_class() -> ValidatronClass {
//!         Self::class_builder()
//!             .struct_class_builder()
//!             .add_field("a", Box::new(|t| &t.a))
//!             .add_field("b", Box::new(|t| &t.b))
//!             .add_field("c", Box::new(|t| &t.c))
//!             .build()
//!     }
//! }
//! ```
//!
//! The [ClassBuilder] can build 4 types of class
//! - [Primitive] : representation of a base type. It needs a parsing function and a function to know which operator is available
//! on it and how to use it.
//! - [Struct] : representation of a struct. It needs the description of its fields and how to access each one.
//! - [Enum] : representation of a enum. It needs the description of its fields, including the relative variant, and how to access each one.
//! - [Collection] : representation of a collection. It requires that the current type implements `IntoIterator<Item = &'x U>` if `U` is the
//! type of the items in the collection.

use std::marker::PhantomData;

mod adt;
mod collection;
mod primitive;
mod structure;

pub use adt::*;
pub use collection::*;
pub use primitive::*;
pub use structure::*;

use crate::HandleOperatorFn;

/// The trait at the core of validatron.
///
/// A type implementing this trait exposes details on the type itself.
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

/// Main entrypoint to build a [ValidatronClass].
pub struct ClassBuilder<T> {
    _phantom: PhantomData<T>,
}

impl<T: Validatron + Send + Sync + 'static> ClassBuilder<T> {
    pub fn primitive(
        self,
        parse_fn: ParseFn<T>,
        handle_op_fn: HandleOperatorFn<T>,
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
        CollectionClassBuilder::create_class::<T, U>()
    }
}

/// Contains all the details of the type with which it is associated.
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

/// Inner type of a [ValidatronClass].
pub enum ValidatronClassKind {
    Primitive(Primitive),
    Struct(Struct),
    Enum(Enum),
    Collection(Collection),
}
