use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    parse_macro_input, punctuated::Punctuated, spanned::Spanned, token::Comma, Attribute, DataEnum,
    DataStruct, DeriveInput, Error, Fields, Index, Variant,
};

/// Procedural macro for implementing the `Validatron` trait for custom types.
///
/// Basically it does the boring task of describing a new types using
/// `Validatron` classes.
///
/// Example:
///
/// ```ignore
/// use validatron::Validatron;
///
/// #[derive(Debug, Clone, Validatron)]
/// pub struct MyStruct {
///     pub a: i32,
///     pub b: i32,
///     pub c: i32,
/// }
/// ```
///
/// In this specific case the macro generates the following code:
///
/// ```ignore
/// impl Validatron for MyStruct {
///     fn get_class() -> ValidatronClass {
///         Self::class_builder()
///             .struct_class_builder()
///             .add_field("a", Box::new(|t| &t.a))
///             .add_field("b", Box::new(|t| &t.b))
///             .add_field("c", Box::new(|t| &t.c))
///             .build()
///     }
/// }
/// ```
///
/// The first parameter of `add_field` method is the name of the field, the second is
/// the access function for this field given an instance of that type.
///
/// Incase of tuple structs (`struct MyStruct(i32)`) the name of the field is going to be the index (`0`, `1`, etc.).
///
/// Using it on an `enum` type is basically the same:
///
/// ```ignore
/// use validatron::Validatron;
///
/// #[derive(Debug, Clone, Validatron)]
/// enum MyEnum {
///     Named { int: i32, float: f64 },
///     Unnamed(i32, String),
/// }
/// ```
///
/// And it will generate the following code:
///
/// ```ignore
/// impl Validatron for MyEnum {
///     fn get_class() -> ValidatronClass {
///         Self::class_builder()
///             .enum_class_builder()
///             .add_variant_field(
///                 "Named",
///                 "int",
///                 Box::new(|t| match &t {
///                     MyEnum::Named { int, .. } => Some(int),
///                     _ => None,
///                 }),
///             )
///             .add_variant_field(
///                 "Named",
///                 "float",
///                 Box::new(|t| match &t {
///                     MyEnum::Named { float, .. } => Some(float),
///                     _ => None,
///                 }),
///             )
///             .add_variant_field(
///                 "Unnamed",
///                 "0",
///                 Box::new(|t| match &t {
///                     MyEnum::Unnamed(x,_) => Some(x),
///                     _ => None,
///                 }),
///             )
///             .add_variant_field(
///                 "Unnamed",
///                 "1",
///                 Box::new(|t| match &t {
///                     MyEnum::Unnamed(_,x) => Some(x),
///                     _ => None,
///                 }),
///             )
///             .build()
///     }
/// }
/// ```
///
/// Notice the access function uses an `Option` as return value over the plain value of the implementation for `struct` types.
///
/// The same rules of the previous example applies for named and unnamed field inside
/// the variants.
#[proc_macro_derive(Validatron, attributes(validatron))]
pub fn variant_validatron(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input as DeriveInput);

    match impl_validatron(input) {
        Ok(ts2) => TokenStream::from(ts2),
        Err(err) => TokenStream::from(err.to_compile_error()),
    }
}

fn impl_validatron(input: DeriveInput) -> Result<TokenStream2, Error> {
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let name = &input.ident;

    let fn_body = match input.data {
        syn::Data::Struct(data_struct) => impl_struct(data_struct),
        syn::Data::Enum(data_enum) => impl_enum(data_enum),
        syn::Data::Union(_) => Err(Error::new(input.span(), "Not implemented for union")),
    }?;

    let quote = quote! {
        impl #impl_generics validatron::Validatron for #name #ty_generics #where_clause {
            fn get_class() -> validatron::ValidatronClass {
                #fn_body
            }
        }
    };

    Ok(quote)
}

fn impl_struct(data_struct: DataStruct) -> Result<TokenStream2, Error> {
    let fields = process_struct_fields(&data_struct.fields)?;

    let quote = quote! {
        Self::class_builder()
            .struct_class_builder()
            #fields
            .build()
    };

    Ok(quote)
}

fn process_struct_fields(fields: &Fields) -> Result<TokenStream2, Error> {
    let add_field_lines = match fields {
        Fields::Named(fields_named) => {
            let add_field_lines: Vec<_> = fields_named
                .named
                .iter()
                .filter(|field| !is_skip(&field.attrs))
                .map(|field| {
                    // Safe because we are processing named fields
                    let field_ident = match field.ident {
                        Some(ref i) => i,
                        None => unreachable!(),
                    };

                    let field_name = field_ident.to_string();

                    quote! {
                       .add_field(#field_name, Box::new(|x| &x.#field_ident))
                    }
                })
                .collect();

            Ok(add_field_lines)
        }
        Fields::Unnamed(fields_unnamed) => {
            let add_field_lines: Vec<_> = fields_unnamed
                .unnamed
                .iter()
                .enumerate()
                .filter(|(_index, field)| !is_skip(&field.attrs))
                .map(|(index, _field)| {
                    let field_ident = Index::from(index);

                    let field_name = index.to_string();

                    quote! {
                       .add_field(#field_name, Box::new(|x| &x.#field_ident))
                    }
                })
                .collect();

            Ok(add_field_lines)
        }
        Fields::Unit => Err(Error::new(
            fields.span(),
            "Not implemented for struct unit fields",
        )),
    }?;

    let quote = quote! {
        #(#add_field_lines)*
    };

    Ok(quote)
}

fn impl_enum(data_enum: DataEnum) -> Result<TokenStream2, Error> {
    let fields = process_enum_fields(&data_enum.variants)?;

    let quote = quote! {
        Self::class_builder()
            .enum_class_builder()
            #fields
            .build()
    };

    Ok(quote)
}

fn process_enum_fields(variants: &Punctuated<Variant, Comma>) -> Result<TokenStream2, Error> {
    let add_field_lines = variants
        .iter()
        .map(|variant| {
            let variant_ident = &variant.ident;
            let variant_name = variant_ident.to_string();

            if is_skip(&variant.attrs) {
                return Ok(quote!());
            }

            let variant_add_field_lines = match &variant.fields {
                syn::Fields::Named(fields_named) => {
                    let variant_add_field_lines: Vec<_> = fields_named
                        .named
                        .iter()
                        .filter(|field| !is_skip(&field.attrs) )
                        .map(|field| {
                            // Safe because we are processing named fields
                            let field_ident = match field.ident {
                                Some(ref i) => i,
                                None => unreachable!(),
                            };

                            let field_name = field_ident.to_string();

                            quote! {
                            .add_variant_field(
                                    #variant_name,
                                    #field_name,
                                    Box::new(|t| match &t {
                                        Self::#variant_ident { #field_ident, .. } => Some(#field_ident),
                                        _ => None,
                                    }),
                                )
                            }
                        })
                        .collect();

                    Ok(quote! {
                        #(#variant_add_field_lines)*
                    })
                }
                syn::Fields::Unnamed(fields_unnamed) => {
                    let fields_num = fields_unnamed.unnamed.len();

                    let variant_add_field_lines: Vec<_> = fields_unnamed
                        .unnamed
                        .iter()
                        .enumerate()
                        .filter(|(_index,field)| !is_skip(&field.attrs) )
                        .map(|(index, _field)| {
                            let field_name = index.to_string();

                            let underscore_before =
                                (0..index).map(|_|{
                                    quote!(_,)
                                });

                            let underscore_after =
                                (index+1..fields_num).map(|_|{
                                    quote!(_,)
                                });

                            quote! {
                            .add_variant_field(
                                    #variant_name,
                                    #field_name,
                                    Box::new(|t| match &t {
                                        Self::#variant_ident (
                                            #(#underscore_before)*
                                            x,
                                            #(#underscore_after)*
                                        ) => Some(x),
                                        _ => None,
                                    }),
                                )
                            }
                        })
                        .collect();

                    Ok(quote! {
                        #(#variant_add_field_lines)*
                    })
                }
                syn::Fields::Unit => Err(Error::new(
                    variant.fields.span(),
                    "Unit fields not supported, try to skip it {:?}"
                )),
            };

            variant_add_field_lines
        })
        .collect::<Result<Vec<TokenStream2>, Error>>()?;

    Ok(quote! {
        #(#add_field_lines)*
    })
}

fn is_skip(attrs: &Vec<Attribute>) -> bool {
    for attr in attrs {
        let mut skip = false;

        if attr.path().is_ident("validatron") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("skip") {
                    skip = true;
                    Ok(())
                } else {
                    Err(meta.error("unsupported attribute"))
                }
            })
            .unwrap();
        }

        if skip {
            return true;
        }
    }
    false
}
