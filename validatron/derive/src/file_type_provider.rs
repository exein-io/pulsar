use proc_macro::TokenStream;

use quote::quote;
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, Error};

pub fn impl_file_type_provider(input: DeriveInput) -> Result<TokenStream, Error> {
    let fn_body = match input.data {
        Data::Struct(_) => Ok(quote! {
            let validate_field = <Self as validatron::ValidatronStruct>::validate_field;
            validatron::ValidatronType::Struct(Box::new(validate_field))
        }),
        Data::Enum(_) => Err("Not implemented for enum"),
        Data::Union(_) => Err("Not implemented for union"),
    }
    .map_err(|err| Error::new(input.span(), err))?;

    let name = &input.ident;

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let quote = quote! {
        impl #impl_generics validatron::ValidatronTypeProvider for #name #ty_generics #where_clause {
            fn field_type() -> validatron::ValidatronType<Self> {
                #fn_body
            }
        }
    };

    Ok(TokenStream::from(quote))
}
