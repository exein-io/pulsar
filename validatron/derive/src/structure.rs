use proc_macro2::TokenStream as TokenStream2;

use quote::quote;
use syn::{
    parse_quote, spanned::Spanned, Data, DataStruct, DeriveInput, Error, GenericParam, Generics,
};

use crate::utils::{ensure_named_fields, validate_fields_named};

pub fn impl_struct_validatron(input: DeriveInput) -> Result<TokenStream2, Error> {
    let data_struct = ensure_struct(&input)?;

    let fields = ensure_named_fields(&data_struct.fields)?;

    // Get name
    let name = &input.ident;

    let validate_fn_body = validate_fields_named(fields, None)?;

    let generics = add_trait_bounds(input.generics);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    Ok(quote! {
        // The generated impl.
        impl #impl_generics validatron::ValidatronStruct for #name #ty_generics #where_clause {

            fn validate_field(
                field_compare: &validatron::Field,
                op: validatron::Operator,
                value: &str,
            ) -> Result<Box<dyn Fn(&Self) -> bool + Send + Sync>, validatron::ValidatronError> {
                #validate_fn_body
            }

        }
    })
}

// TODO: Add a bound `T: ValidatronVariant` to every type parameter T.
fn add_trait_bounds(mut generics: Generics) -> Generics {
    for param in &mut generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            type_param
                .bounds
                .push(parse_quote!(validatron::Sttructvalidatron));
        }
    }

    generics
}

fn ensure_struct(input: &DeriveInput) -> Result<&DataStruct, Error> {
    let data_enum = match input.data {
        Data::Struct(ref data_struct) => Ok(data_struct),
        Data::Enum(_) => Err("Not implemented for enum"),
        Data::Union(_) => Err("Not implemented for union"),
    };
    data_enum.map_err(|err| Error::new(input.span(), err))
}
