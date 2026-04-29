use quote::quote;
use syn::LitStr;

use crate::level::TelemetryLevel;

pub(crate) fn submit_span_metadata(
    target: &LitStr,
    level: TelemetryLevel,
    name: &LitStr,
    description: Option<&LitStr>,
) -> proc_macro2::TokenStream {
    let level = level.metadata_tokens();
    let description = match description {
        Some(description) => quote! { ::core::option::Option::Some(#description) },
        None => quote! { ::core::option::Option::None },
    };

    quote! {
        ::miden_node_tracing::inventory::submit! {
            ::miden_node_tracing::SpanMetadata {
                target: #target,
                level: #level,
                name: #name,
                description: #description,
            }
        }
    }
}
