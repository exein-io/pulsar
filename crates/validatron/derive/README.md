# Validatron derive macros

Procedural macro for implementing the `Validatron` trait for custom types.

Basically it does the boring task of describing a new types using `Validatron` classes.

Example:

```rust
use validatron::Validatron;

#[derive(Debug, Clone, Validatron)]
pub struct MyStruct {
    pub a: i32,
    pub b: i32,
    pub c: i32,
}
```

In this specific case the macro generates the following code:

```rust
impl Validatron for MyStruct {
    fn get_class() -> ValidatronClass {
        Self::class_builder()
            .struct_class_builder()
            .add_field("a", Box::new(|t| &t.a))
            .add_field("b", Box::new(|t| &t.b))
            .add_field("c", Box::new(|t| &t.c))
            .build()
    }
}
```

The first parameter of `add_field` method is the name of the field, the second is
the access function for this field given an instance of that type.

Incase of tuple structs (`struct MyStruct(i32)`) the name of the field is going to be the index (`0`, `1`, etc.).

Using it on an `enum` type is basically the same:

```rust
use validatron::Validatron;

#[derive(Debug, Clone, Validatron)]
enum MyEnum {
    Named { int: i32, float: f64 },
    Unnamed(i32, String),
}
```

And it will generate the following code:

```rust
impl Validatron for MyEnum {
    fn get_class() -> ValidatronClass {
        Self::class_builder()
            .enum_class_builder()
            .add_variant_field(
                "Named",
                "int",
                Box::new(|t| match &t {
                    MyEnum::Named { int, .. } => Some(int),
                    _ => None,
                }),
            )
            .add_variant_field(
                "Named",
                "float",
                Box::new(|t| match &t {
                    MyEnum::Named { float, .. } => Some(float),
                    _ => None,
                }),
            )
            .add_variant_field(
                "Unnamed",
                "0",
                Box::new(|t| match &t {
                    MyEnum::Unnamed(x,_) => Some(x),
                    _ => None,
                }),
            )
            .add_variant_field(
                "Unnamed",
                "1",
                Box::new(|t| match &t {
                    MyEnum::Unnamed(_,x) => Some(x),
                    _ => None,
                }),
            )
            .build()
    }
}
```

Notice the access function uses an `Option` as return value over the plain value of the implementation for `struct` types.

The same rules of the previous example applies for named and unnamed field inside
the variants.

