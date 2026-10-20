//! Procedural macro for deriving the `GrpcError` trait on error enums.
//!
//! This macro simplifies the creation of gRPC-compatible error enums by automatically:
//! - Generating a companion error enum for gRPC serialization
//! - Implementing the `GrpcError` trait
//! - Providing proper error code mappings
//! - Generating `From<Error> for tonic::Status` conversion
//! - Classifying each variant for telemetry by its gRPC status code
//!
//! # Example
//!
//! ```rust,ignore
//! use miden_node_grpc_error_macro::GrpcError;
//! use thiserror::Error;
//!
//! #[derive(Debug, Error, GrpcError)]
//! pub enum GetNoteScriptByRootError {
//!     #[error("database error")]
//!     #[grpc(internal)]
//!     DatabaseError(#[from] DatabaseError),
//!     
//!     #[error("malformed script root")]
//!     DeserializationFailed,
//!     
//!     #[error("script with given root doesn't exist")]
//!     ScriptNotFound,
//! }
//! ```

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Ident, parse_macro_input};

/// Derives the `GrpcError` trait for an error enum.
///
/// # Attributes
///
/// - `#[grpc(internal)]` - Marks a variant as an internal error (will map to
///   `tonic::Code::Internal`)
///
/// # Generated Code
///
/// This macro generates:
/// 1. A companion `*GrpcError` enum with `#[repr(u8)]` for wire serialization
/// 2. An implementation of the `GrpcError` trait for the companion enum
/// 3. A method `api_error()` on the original enum that maps to the companion enum
/// 4. An implementation of `From<Error> for tonic::Status` for automatic error conversion
/// 5. An implementation of `miden_node_tracing::Classified` that classifies each variant by its
///    gRPC status code, with the variant's name in snake case as the failure kind
#[proc_macro_derive(GrpcError, attributes(grpc))]
pub fn derive_grpc_error(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;
    let vis = &input.vis;
    let grpc_name = Ident::new(&format!("{name}GrpcError"), name.span());

    let variants = match &input.data {
        Data::Enum(data) => &data.variants,
        _ => {
            return syn::Error::new_spanned(name, "GrpcError can only be derived for enums")
                .to_compile_error()
                .into();
        },
    };

    // Build the GrpcError enum variants
    let mut grpc_variants = Vec::new();
    let mut api_error_arms = Vec::new();
    let mut failure_kind_arms = Vec::new();

    // Always add Internal variant (standard practice for gRPC errors)
    grpc_variants.push(quote! {
        /// Internal server error
        Internal = 0
    });
    let mut discriminant = 1u8;

    for variant in variants {
        let variant_name = &variant.ident;
        let pattern = variant_pattern(name, variant);
        let kind = snake_case(&variant_name.to_string());
        failure_kind_arms.push(quote! { #pattern => #kind });

        // Check if this variant is marked as internal
        let is_internal = variant.attrs.iter().any(|attr| {
            attr.path().is_ident("grpc")
                && attr.parse_args::<Ident>().is_ok_and(|i| i == "internal")
        });

        // Extract doc comments
        let docs: Vec<_> =
            variant.attrs.iter().filter(|attr| attr.path().is_ident("doc")).collect();

        if is_internal {
            // Map to Internal variant
            api_error_arms.push(quote! {
                #pattern => #grpc_name::Internal
            });
        } else {
            // Create a corresponding variant in GrpcError enum
            grpc_variants.push(quote! {
                #(#docs)*
                #variant_name = #discriminant
            });

            api_error_arms.push(quote! {
                #pattern => #grpc_name::#variant_name
            });

            discriminant += 1;
        }
    }

    let expanded = quote! {
        #[derive(Debug, Copy, Clone, PartialEq, Eq)]
        #[repr(u8)]
        #vis enum #grpc_name {
            #(#grpc_variants,)*
        }

        impl #grpc_name {
            /// Returns the error code for this gRPC error.
            pub fn api_code(self) -> u8 {
                self as u8
            }

            /// Returns true if this is an internal server error.
            pub fn is_internal(&self) -> bool {
                matches!(self, Self::Internal)
            }

            /// Returns the appropriate tonic code for this error.
            pub fn tonic_code(&self) -> tonic::Code {
                if self.is_internal() {
                    tonic::Code::Internal
                } else {
                    tonic::Code::InvalidArgument
                }
            }
        }

        impl #name {
            /// Maps this error to its gRPC error code representation.
            pub fn api_error(&self) -> #grpc_name {
                match self {
                    #(#api_error_arms,)*
                }
            }
        }

        impl ::miden_node_tracing::Classified for #name {
            fn failure_class(&self) -> ::miden_node_tracing::FailureClass {
                let kind = match self {
                    #(#failure_kind_arms,)*
                };
                ::miden_node_tracing::FailureClass::from_grpc_code(self.api_error().tonic_code())
                    .with_kind(kind)
            }
        }

        // Automatically implement From<Error> for tonic::Status
        impl From<#name> for tonic::Status {
            fn from(value: #name) -> Self {
                let api_error = value.api_error();

                let message = if api_error.is_internal() {
                    "Internal error".to_owned()
                } else {
                    // Use ErrorReport trait to get detailed error message
                    use miden_node_tracing::ErrorReport as _;
                    value.as_report()
                };

                tonic::Status::with_details(
                    api_error.tonic_code(),
                    message,
                    vec![api_error.api_code()].into(),
                )
            }
        }
    };

    TokenStream::from(expanded)
}

/// Returns the pattern that matches a variant regardless of its fields.
fn variant_pattern(name: &Ident, variant: &syn::Variant) -> proc_macro2::TokenStream {
    let variant_name = &variant.ident;
    match &variant.fields {
        Fields::Unit => quote! { #name::#variant_name },
        Fields::Unnamed(_) => quote! { #name::#variant_name(..) },
        Fields::Named(_) => quote! { #name::#variant_name { .. } },
    }
}

/// Converts an `UpperCamelCase` identifier to `snake_case`.
fn snake_case(name: &str) -> String {
    let mut snake = String::with_capacity(name.len() + 4);
    for (index, character) in name.char_indices() {
        if character.is_uppercase() {
            if index > 0 {
                snake.push('_');
            }
            snake.extend(character.to_lowercase());
        } else {
            snake.push(character);
        }
    }
    snake
}
