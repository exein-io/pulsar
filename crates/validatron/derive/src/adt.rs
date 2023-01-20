use proc_macro::TokenStream;
use proc_macro2::{Ident, TokenStream as TokenStream2};

use quote::quote;
use syn::{
    parse_quote, spanned::Spanned, Data, DataEnum, DeriveInput, Error, FieldsNamed, GenericParam,
    Generics,
};

use crate::utils::validate_fields_named;

pub fn impl_variant_validatron(input: DeriveInput) -> Result<TokenStream, Error> {
    let data_enum = ensure_enum(&input)?;

    // Get name
    let name = &input.ident;

    let validate_fn_body = validate_fn_body(&input.ident, data_enum)?;

    let var_num_fn_body = var_num_fn_body(&input.ident, data_enum);

    let var_num_of_fn_body = var_num_of_fn_body(data_enum);

    let generics = add_trait_bounds(input.generics);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        // The generated impl.
        impl #impl_generics validatron::ValidatronVariant for #name #ty_generics #where_clause {

            fn validate(
                variant: &str,
                field_compare: &validatron::Field,
                op: validatron::Operator,
                value: &str,
            ) -> Result<(usize, Box<dyn Fn(&Self) -> bool + Send + Sync>), validatron::ValidatronError> {
                #validate_fn_body

            }

            fn var_num(&self) -> usize {
                #var_num_fn_body
            }

            fn var_num_of(variant: &str) -> Result<usize, validatron::ValidatronError> {
                #var_num_of_fn_body
            }
        }
    };

    // Hand the output tokens back to the compiler.
    Ok(TokenStream::from(expanded))
}

// TODO: Add a bound `T: ValidatronVariant` to every type parameter T.

fn add_trait_bounds(mut generics: Generics) -> Generics {
    for param in &mut generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            type_param
                .bounds
                .push(parse_quote!(validatron::ValidatronVariant));
        }
    }
    generics
}

fn ensure_enum(input: &DeriveInput) -> Result<&DataEnum, Error> {
    let data_enum = match input.data {
        Data::Struct(_) => Err("Not implemented for struct"),
        Data::Enum(ref data_enum) => Ok(data_enum),
        Data::Union(_) => Err("Not implemented for union"),
    };
    data_enum.map_err(|err| Error::new(input.span(), err))
}

fn var_num_of_fn_body(data_enum: &DataEnum) -> TokenStream2 {
    let var_num_match_arms = data_enum.variants.iter().enumerate().map(|(pos, variant)| {
        let variant_ident = &variant.ident.to_string();
        quote! {
            #variant_ident => Ok(#pos)
        }
    });

    quote! {
        match variant {
            #(#var_num_match_arms,)*
            _ => Err(validatron::ValidatronError::ViariantNotFound(variant.to_string())),
        }
    }
}

fn validate_fn_body(enum_ident: &Ident, data_enum: &DataEnum) -> Result<TokenStream2, Error> {
    let check_result_arms = data_enum
        .variants
        .iter()
        .map(|variant| {
            let variant_ident = &variant.ident;

            match &variant.fields {
                syn::Fields::Named(fields_named) => {
                    handle_named_field_enum(enum_ident, variant_ident, fields_named)
                }
                syn::Fields::Unit => Ok(handle_unit_enum(variant_ident)),
                syn::Fields::Unnamed(_) => Err(Error::new(
                    variant.fields.span(),
                    "Unnamed fields not supported",
                )),
            }
        })
        .collect::<Result<Vec<TokenStream2>, Error>>()?;

    let token_stream = quote! {
        let var_num = Self::var_num_of(variant)?;

        let check_result = match variant {
            #(#check_result_arms,)*
            _ => return Err(validatron::ValidatronError::ViariantNotFound(variant.to_string())),
        };


        check_result.map(|validated_condition| (var_num, validated_condition))
    };

    Ok(token_stream)
}

fn handle_unit_enum(variant_ident: &Ident) -> TokenStream2 {
    let variant_ident_string = variant_ident.to_string();
    quote! {

        #variant_ident_string => {
            Err(validatron::ValidatronError::FieldNotFound(field_compare.to_string()))
        }

    }
}

fn handle_named_field_enum(
    enum_ident: &Ident,
    variant_ident: &Ident,
    fields_named: &FieldsNamed,
) -> Result<TokenStream2, Error> {
    let variant_ident_string = variant_ident.to_string();

    let extract_fn = |field_ident: &Ident| {
        quote! {
            match s {
                #enum_ident::#variant_ident { #field_ident, .. } => Some(#field_ident),
                _ => None,
            }
        }
    };

    let validate_fn_body = validate_fields_named(fields_named, Some(&extract_fn))?;

    Ok(quote! {

        #variant_ident_string => {
            #validate_fn_body
        }

    })
}

fn var_num_fn_body(ident: &Ident, data_enum: &DataEnum) -> TokenStream2 {
    let match_arms = data_enum.variants.iter().enumerate().map(|(pos, variant)| {
        let variant_ident = &variant.ident;
        quote! {

            #ident::#variant_ident { .. } => #pos
        }
    });

    quote! {
        match self {
            #(#match_arms,)*
        }
    }
}
