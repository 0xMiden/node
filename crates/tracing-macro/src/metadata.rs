use quote::quote;
use syn::LitStr;

use crate::level::TelemetryLevel;

pub(crate) fn submit_span_metadata(
    target: &LitStr,
    level: TelemetryLevel,
    name: &LitStr,
    description: Option<&LitStr>,
    user: bool,
) -> proc_macro2::TokenStream {
    let level = level.metadata_tokens();
    let description = match description {
        Some(description) => quote! { ::core::option::Option::Some(#description) },
        None => quote! { ::core::option::Option::None },
    };
    quote! {
        ::miden_node_tracing::__private::inventory::submit! {
            ::miden_node_tracing::TelemetryMetadata::Span(
                ::miden_node_tracing::SpanMetadata {
                    target: #target,
                    level: #level,
                    name: #name,
                    description: #description,
                    user: #user,
                }
            )
        }
    }
}

pub(crate) fn submit_event_metadata(
    target: &LitStr,
    level: TelemetryLevel,
    message: &LitStr,
    user: bool,
) -> proc_macro2::TokenStream {
    let level = level.metadata_tokens();

    quote! {
        ::miden_node_tracing::__private::inventory::submit! {
            ::miden_node_tracing::TelemetryMetadata::Event(
                ::miden_node_tracing::EventMetadata {
                    target: #target,
                    level: #level,
                    message: #message,
                    user: #user,
                }
            )
        }
    }
}
