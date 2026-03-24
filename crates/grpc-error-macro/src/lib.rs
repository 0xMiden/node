//! Procedural macro for deriving the `GrpcError` trait on error enums.
//!
//! This macro simplifies the creation of gRPC-compatible error enums by automatically:
//! - Generating a companion error enum for gRPC serialization
//! - Implementing the `GrpcError` trait
//! - Providing proper error code mappings
//! - Generating `From<Error> for tonic::Status` conversion
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
use syn::visit_mut::VisitMut;
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

    // Always add Internal variant (standard practice for gRPC errors)
    grpc_variants.push(quote! {
        /// Internal server error
        Internal = 0
    });
    let mut discriminant = 1u8;

    for variant in variants {
        let variant_name = &variant.ident;

        // Check if this variant is marked as internal
        let is_internal = variant.attrs.iter().any(|attr| {
            attr.path().is_ident("grpc")
                && attr.parse_args::<Ident>().map(|i| i == "internal").unwrap_or(false)
        });

        // Extract doc comments
        let docs: Vec<_> =
            variant.attrs.iter().filter(|attr| attr.path().is_ident("doc")).collect();

        if is_internal {
            // Map to Internal variant
            let pattern = match &variant.fields {
                Fields::Unit => quote! { #name::#variant_name },
                Fields::Unnamed(_) => quote! { #name::#variant_name(..) },
                Fields::Named(_) => quote! { #name::#variant_name { .. } },
            };

            api_error_arms.push(quote! {
                #pattern => #grpc_name::Internal
            });
        } else {
            // Create a corresponding variant in GrpcError enum
            grpc_variants.push(quote! {
                #(#docs)*
                #variant_name = #discriminant
            });

            let pattern = match &variant.fields {
                Fields::Unit => quote! { #name::#variant_name },
                Fields::Unnamed(_) => quote! { #name::#variant_name(..) },
                Fields::Named(_) => quote! { #name::#variant_name { .. } },
            };

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

        // Automatically implement From<Error> for tonic::Status
        impl From<#name> for tonic::Status {
            fn from(value: #name) -> Self {
                let api_error = value.api_error();

                let message = if api_error.is_internal() {
                    "Internal error".to_owned()
                } else {
                    // Use ErrorReport trait to get detailed error message
                    use miden_node_utils::ErrorReport as _;
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

// GRPC DECODE ATTRIBUTE MACRO
// ================================================================================================

/// Attribute macro that rewrites `.decode()` shorthand into
/// `decoder.decode_field("field_name", value.field_name)` calls.
///
/// Place on an `impl TryFrom<ProtoType> for DomainType` block. The macro will:
/// 1. Find all `<param>.field.decode()` calls in each method body
/// 2. Inject `let decoder = <param>.decoder();` at the top of the method
/// 3. Rewrite each `.decode()` call to `decoder.decode_field("field", <param>.field)`
///
/// The field name string is extracted from the last segment of the field access expression.
/// Calls inside closures are **not** rewritten (closures have their own receiver scope).
///
/// # Example
///
/// ```rust,ignore
/// #[grpc_decode]
/// impl TryFrom<proto::blockchain::BlockHeader> for BlockHeader {
///     type Error = ConversionError;
///     fn try_from(value: proto::blockchain::BlockHeader) -> Result<Self, Self::Error> {
///         let prev = value.prev_block_commitment.decode()?;
///         let chain = value.chain_commitment.decode()?;
///         // Non-decode code passes through unchanged:
///         Ok(BlockHeader::new(value.version, prev, value.block_num.into(), chain))
///     }
/// }
/// ```
///
/// Expands to:
///
/// ```rust,ignore
/// impl TryFrom<proto::blockchain::BlockHeader> for BlockHeader {
///     type Error = ConversionError;
///     fn try_from(value: proto::blockchain::BlockHeader) -> Result<Self, Self::Error> {
///         let decoder = value.decoder();
///         let prev = decoder.decode_field("prev_block_commitment", value.prev_block_commitment)?;
///         let chain = decoder.decode_field("chain_commitment", value.chain_commitment)?;
///         Ok(BlockHeader::new(value.version, prev, value.block_num.into(), chain))
///     }
/// }
/// ```
#[proc_macro_attribute]
pub fn grpc_decode(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut impl_block = parse_macro_input!(item as syn::ItemImpl);

    for item in &mut impl_block.items {
        if let syn::ImplItem::Fn(method) = item {
            process_method(method);
        }
    }

    TokenStream::from(quote!(#impl_block))
}

/// Processes a single method in the impl block, rewriting `.decode()` calls.
fn process_method(method: &mut syn::ImplItemFn) {
    let Some(param_name) = extract_param_name(&method.sig) else {
        return;
    };

    let mut rewriter = DecodeRewriter {
        param_name: param_name.clone(),
        found_decode: false,
        closure_depth: 0,
    };

    syn::visit_mut::visit_block_mut(&mut rewriter, &mut method.block);

    if rewriter.found_decode {
        let decoder_stmt: syn::Stmt = syn::parse_quote! {
            let decoder = #param_name.decoder();
        };
        method.block.stmts.insert(0, decoder_stmt);
    }
}

/// Extracts the first non-self parameter name from a function signature.
fn extract_param_name(sig: &syn::Signature) -> Option<Ident> {
    for arg in &sig.inputs {
        if let syn::FnArg::Typed(pat_type) = arg {
            if let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                return Some(pat_ident.ident.clone());
            }
        }
    }
    None
}

/// AST visitor that rewrites `<param>.field.decode()` →
/// `decoder.decode_field("field", <param>.field)`.
struct DecodeRewriter {
    /// The function parameter name (e.g., `value`, `response`, `from`).
    param_name: Ident,
    /// Whether any `.decode()` calls were found and rewritten.
    found_decode: bool,
    /// Current closure nesting depth — skip rewriting when > 0.
    closure_depth: u32,
}

impl DecodeRewriter {
    /// Checks if a field access expression is rooted at the function parameter,
    /// and returns the last field name segment if so.
    fn extract_field_info(&self, expr: &syn::Expr) -> Option<Ident> {
        if let syn::Expr::Field(field_expr) = expr {
            if let syn::Member::Named(field_ident) = &field_expr.member {
                if self.root_is_param(expr) {
                    return Some(field_ident.clone());
                }
            }
        }
        None
    }

    /// Recursively checks if the root of a field access chain is the function parameter.
    fn root_is_param(&self, expr: &syn::Expr) -> bool {
        match expr {
            syn::Expr::Path(path) => path.path.is_ident(&self.param_name),
            syn::Expr::Field(field) => self.root_is_param(&field.base),
            _ => false,
        }
    }
}

impl VisitMut for DecodeRewriter {
    fn visit_expr_mut(&mut self, expr: &mut syn::Expr) {
        // Recurse into children first (bottom-up).
        syn::visit_mut::visit_expr_mut(self, expr);

        // Skip rewriting inside closures.
        if self.closure_depth > 0 {
            return;
        }

        // Match: <receiver>.decode() with no arguments.
        if let syn::Expr::MethodCall(mc) = expr {
            if mc.method == "decode" && mc.args.is_empty() {
                if let Some(field_name) = self.extract_field_info(&mc.receiver) {
                    let receiver = &mc.receiver;
                    let name_str = field_name.to_string();
                    self.found_decode = true;
                    *expr = syn::parse_quote! {
                        decoder.decode_field(#name_str, #receiver)
                    };
                }
            }
        }
    }

    fn visit_expr_closure_mut(&mut self, closure: &mut syn::ExprClosure) {
        self.closure_depth += 1;
        syn::visit_mut::visit_expr_closure_mut(self, closure);
        self.closure_depth -= 1;
    }
}
