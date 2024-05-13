use bpf_features::BpfFeatures;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};

/// Generates a mapping of `BpfFeatures` to eBPF program bytes. The bytes are
/// embedded into the final binary thanks to `include_bytes_aligned`.
#[proc_macro]
pub fn ebpf_programs_map(input: TokenStream) -> TokenStream {
    let probe = parse_macro_input!(input as LitStr).value();

    let mut tokens = quote! {};

    for (features, (bpf_objfile_suffix, _)) in BpfFeatures::all_combinations() {
        let path = format!(
            "{}/{}.{}",
            std::env::var("OUT_DIR").unwrap(),
            probe,
            bpf_objfile_suffix
        );
        tokens = quote! {
            #tokens
            (#features, bpf_common::aya::include_bytes_aligned!(#path)),
        };
    }

    let tokens = quote! {
        [#tokens]
    };

    tokens.into()
}
