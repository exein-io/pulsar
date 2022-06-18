use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod adt;
mod file_type_provider;
mod structure;
mod utils;

#[proc_macro_derive(ValidatronVariant, attributes(validatron))]
pub fn variant_validatron(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input as DeriveInput);

    match adt::impl_variant_validatron(input) {
        Ok(ts2) => ts2,
        Err(err) => TokenStream::from(err.to_compile_error()),
    }
}

#[proc_macro_derive(ValidatronStruct, attributes(validatron))]
pub fn struct_validatron(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input as DeriveInput);

    match structure::impl_struct_validatron(input) {
        Ok(ts2) => TokenStream::from(ts2),
        Err(err) => TokenStream::from(err.to_compile_error()),
    }
}

#[proc_macro_derive(ValidatronTypeProvider)]
pub fn file_type_provider(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input as DeriveInput);

    match file_type_provider::impl_file_type_provider(input) {
        Ok(ts2) => ts2,
        Err(err) => TokenStream::from(err.to_compile_error()),
    }
}
