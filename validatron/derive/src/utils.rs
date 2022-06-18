use proc_macro2::{Ident, TokenStream as TokenStream2};
use quote::quote;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::token::Comma;
use syn::{Error, Fields, FieldsNamed, Meta, NestedMeta};

pub fn ensure_named_fields(fields: &Fields) -> Result<&FieldsNamed, Error> {
    let retval = match fields {
        Fields::Named(named) => Ok(named),
        Fields::Unnamed(_) => Err("Only named fields are supported. This is an unnamed field."),
        Fields::Unit => Err("Only named fields are supported. This is a unit field."),
    };
    retval.map_err(|err| Error::new(fields.span(), err))
}

fn validatron_metas(meta: &Meta) -> Option<&Punctuated<NestedMeta, Comma>> {
    if let Meta::List(list) = meta {
        if let Some(segment) = list.path.segments.first() {
            if segment.ident == "validatron" {
                return Some(&list.nested);
            }
        }
    }
    None
}

fn is_skip(nested_meta: &NestedMeta) -> bool {
    if let NestedMeta::Meta(Meta::Path(path)) = nested_meta {
        if let Some(segment) = path.segments.first() {
            if segment.ident == "skip" {
                return true;
            }
        }
    }
    false
}

pub fn validate_fields_named(
    fields: &FieldsNamed,
    extract_fn_body: Option<&dyn Fn(&Ident) -> TokenStream2>,
) -> Result<TokenStream2, Error> {
    let fvds = fields
        .named
        .iter()
        .filter(|&field| {
            for attr in &field.attrs {
                let meta = attr.parse_meta().unwrap(); // TODO:

                if let Some(nested_metas) = validatron_metas(&meta) {
                    if nested_metas.iter().any(is_skip) {
                        return false;
                    }
                }
            }
            true
        })
        .map(|field| {
            let field_ident = match field.ident {
                Some(ref i) => i,
                None => unreachable!(),
            };
            let field_name = field_ident.to_string();

            let default_body = quote! {

                Some(&s.#field_ident)
            };

            let extract_fn_body = extract_fn_body
                .map(|f| f(field_ident))
                .unwrap_or(default_body);

            quote! {
                validatron::process_field(
                    #field_name,
                    field_compare,
                    |s: &Self| #extract_fn_body,
                    op.clone(),
                    value,
                )
            }
        });

    let token_stream = quote! {
        let field_checks: Vec<Option<Result<Box<dyn Fn(&Self) -> bool + Send + Sync>, validatron::ValidatronError>>> = vec![

            #(#fvds,)*
        ];
        let matched = field_checks
            .into_iter()
            .filter_map(std::convert::identity)
            .next();

        matched.ok_or(validatron::ValidatronError::FieldNotFound(field_compare.to_string()))?
    };

    Ok(token_stream)
}
