use quote::quote;
use syn::LitStr;

use crate::level::SpanLevel;

pub(crate) fn submit_span_metadata(
    target: &LitStr,
    level: SpanLevel,
    name: &LitStr,
) -> proc_macro2::TokenStream {
    let level = level.metadata_tokens();

    quote! {
        ::miden_node_tracing::inventory::submit! {
            ::miden_node_tracing::SpanMetadata {
                target: #target,
                level: #level,
                name: #name,
            }
        }
    }
}
