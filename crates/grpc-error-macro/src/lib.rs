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
/// `.decode()` calls inside closures, for-loops, and match arms are also rewritten
/// when the receiver is rooted at the closure parameter, loop variable, or match binding.
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
        roots: vec![param_name.clone()],
        found_decode: false,
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

/// Extracts all ident bindings from a pattern (e.g., `Foo::Bar(x)` → `[x]`).
fn extract_pat_idents(pat: &syn::Pat) -> Vec<Ident> {
    let mut idents = Vec::new();
    collect_pat_idents(pat, &mut idents);
    idents
}

fn collect_pat_idents(pat: &syn::Pat, idents: &mut Vec<Ident>) {
    match pat {
        syn::Pat::Ident(pat_ident) => {
            idents.push(pat_ident.ident.clone());
        },
        syn::Pat::TupleStruct(tuple_struct) => {
            for elem in &tuple_struct.elems {
                collect_pat_idents(elem, idents);
            }
        },
        syn::Pat::Tuple(tuple) => {
            for elem in &tuple.elems {
                collect_pat_idents(elem, idents);
            }
        },
        syn::Pat::Struct(pat_struct) => {
            for field in &pat_struct.fields {
                collect_pat_idents(&field.pat, idents);
            }
        },
        syn::Pat::Reference(pat_ref) => {
            collect_pat_idents(&pat_ref.pat, idents);
        },
        _ => {},
    }
}

/// Injects `let decoder = <root>.decoder();` at the start of a block.
fn inject_decoder_into_block(block: &mut syn::Block, root: &Ident) {
    let decoder_stmt: syn::Stmt = syn::parse_quote! {
        let decoder = #root.decoder();
    };
    block.stmts.insert(0, decoder_stmt);
}

/// AST visitor that rewrites `<root>.field.decode()` →
/// `decoder.decode_field("field", <root>.field)`.
///
/// Tracks a stack of "roots" — variable names that are valid decode receivers.
/// The function parameter is the initial root. Closure parameters, for-loop
/// variables, and match bindings are pushed as temporary roots when visiting
/// their respective scopes.
struct DecodeRewriter {
    /// Stack of decode root variable names.
    roots: Vec<Ident>,
    /// Whether any `.decode()` calls were found and rewritten at the top-level
    /// (function parameter) scope.
    found_decode: bool,
}

impl DecodeRewriter {
    /// Checks if a field access expression is rooted at any known root,
    /// and returns the last field name segment if so.
    fn extract_field_info(&self, expr: &syn::Expr) -> Option<Ident> {
        if let syn::Expr::Field(field_expr) = expr {
            if let syn::Member::Named(field_ident) = &field_expr.member {
                if self.root_matches_any(expr) {
                    return Some(field_ident.clone());
                }
            }
        }
        None
    }

    /// Recursively checks if the root of a field access chain matches any known root.
    fn root_matches_any(&self, expr: &syn::Expr) -> bool {
        match expr {
            syn::Expr::Path(path) => self.roots.iter().any(|root| path.path.is_ident(root)),
            syn::Expr::Field(field) => self.root_matches_any(&field.base),
            _ => false,
        }
    }

    /// Finds which root an expression is rooted at.
    fn find_root(&self, expr: &syn::Expr) -> Option<&Ident> {
        match expr {
            syn::Expr::Path(path) => self.roots.iter().find(|root| path.path.is_ident(&**root)),
            syn::Expr::Field(field) => self.find_root(&field.base),
            _ => None,
        }
    }
}

/// Visitor that detects `decoder.decode_field(...)` calls in the immediate scope,
/// without recursing into nested closures or for-loops (which have their own decoders).
struct DecoderCallFinder(bool);

impl<'ast> syn::visit::Visit<'ast> for DecoderCallFinder {
    fn visit_expr_method_call(&mut self, mc: &'ast syn::ExprMethodCall) {
        if mc.method == "decode_field" {
            if let syn::Expr::Path(path) = &*mc.receiver {
                if path.path.is_ident("decoder") {
                    self.0 = true;
                }
            }
        }
        syn::visit::visit_expr_method_call(self, mc);
    }

    fn visit_expr_closure(&mut self, _: &'ast syn::ExprClosure) {}
    fn visit_expr_for_loop(&mut self, _: &'ast syn::ExprForLoop) {}
}

/// Checks if an expression contains any `decoder.decode_field(...)` calls.
fn expr_contains_decoder_call(expr: &syn::Expr) -> bool {
    let mut finder = DecoderCallFinder(false);
    syn::visit::Visit::visit_expr(&mut finder, expr);
    finder.0
}

/// Checks if a block contains any `decoder.decode_field(...)` calls.
fn block_contains_decoder_call(block: &syn::Block) -> bool {
    let mut finder = DecoderCallFinder(false);
    syn::visit::Visit::visit_block(&mut finder, block);
    finder.0
}

impl VisitMut for DecodeRewriter {
    fn visit_expr_mut(&mut self, expr: &mut syn::Expr) {
        // Recurse into children first (bottom-up).
        syn::visit_mut::visit_expr_mut(self, expr);

        // Match: <receiver>.decode() with no arguments.
        if let syn::Expr::MethodCall(mc) = expr {
            if mc.method == "decode" && mc.args.is_empty() {
                if let Some(field_name) = self.extract_field_info(&mc.receiver) {
                    let root = self.find_root(&mc.receiver).cloned();
                    let receiver = &mc.receiver;
                    let name_str = field_name.to_string();
                    if root.as_ref() == self.roots.first() {
                        self.found_decode = true;
                    }
                    *expr = syn::parse_quote! {
                        decoder.decode_field(#name_str, #receiver)
                    };
                }
            }
        }
    }

    fn visit_expr_closure_mut(&mut self, closure: &mut syn::ExprClosure) {
        // Extract closure parameter idents as new roots.
        let new_roots: Vec<Ident> = closure
            .inputs
            .iter()
            .filter_map(|pat| {
                if let syn::Pat::Ident(pat_ident) = pat {
                    Some(pat_ident.ident.clone())
                } else {
                    None
                }
            })
            .collect();

        if new_roots.is_empty() {
            // No usable closure params — visit normally without adding roots.
            syn::visit_mut::visit_expr_closure_mut(self, closure);
            return;
        }

        // If the closure body is a block, we can inject a decoder statement.
        // If it's an expression, wrap it in a block first.
        let roots_start = self.roots.len();
        self.roots.extend(new_roots);

        syn::visit_mut::visit_expr_closure_mut(self, closure);

        // Check if we need to inject a decoder. Get the root that was used.
        let injected_roots: Vec<Ident> = self.roots[roots_start..].to_vec();
        self.roots.truncate(roots_start);

        // Find which root needs a decoder by checking the closure body.
        // If the body is a block expression, check it directly.
        // If the body is a non-block expression (e.g., single-expression closure),
        // check if the rewritten expression contains decoder.decode_field calls
        // and wrap it in a block with the decoder statement.
        for root in &injected_roots {
            let needs_decoder = match &*closure.body {
                syn::Expr::Block(expr_block) => block_contains_decoder_call(&expr_block.block),
                other => expr_contains_decoder_call(other),
            };

            if needs_decoder {
                if let syn::Expr::Block(expr_block) = &mut *closure.body {
                    inject_decoder_into_block(&mut expr_block.block, root);
                } else {
                    // Wrap the expression body in a block with a decoder statement.
                    let body = &closure.body;
                    *closure.body = syn::parse_quote! {
                        {
                            let decoder = #root.decoder();
                            #body
                        }
                    };
                }
                break;
            }
        }
    }

    fn visit_expr_for_loop_mut(&mut self, for_loop: &mut syn::ExprForLoop) {
        // Extract the loop variable as a new root.
        let new_roots = extract_pat_idents(&for_loop.pat);

        let roots_start = self.roots.len();
        self.roots.extend(new_roots);

        syn::visit_mut::visit_expr_for_loop_mut(self, for_loop);

        let injected_roots: Vec<Ident> = self.roots[roots_start..].to_vec();
        self.roots.truncate(roots_start);

        for root in &injected_roots {
            if block_contains_decoder_call(&for_loop.body) {
                inject_decoder_into_block(&mut for_loop.body, root);
                break; // Only one decoder per block
            }
        }
    }

    fn visit_arm_mut(&mut self, arm: &mut syn::Arm) {
        // Extract match binding idents as new roots.
        let new_roots = extract_pat_idents(&arm.pat);

        let roots_start = self.roots.len();
        self.roots.extend(new_roots);

        syn::visit_mut::visit_arm_mut(self, arm);

        let injected_roots: Vec<Ident> = self.roots[roots_start..].to_vec();
        self.roots.truncate(roots_start);

        // Inject decoder into the arm body if it's a block expression.
        for root in &injected_roots {
            let needs_decoder = match &*arm.body {
                syn::Expr::Block(expr_block) => block_contains_decoder_call(&expr_block.block),
                _ => false,
            };

            if needs_decoder {
                if let syn::Expr::Block(expr_block) = &mut *arm.body {
                    inject_decoder_into_block(&mut expr_block.block, root);
                    break;
                }
            }
        }
    }
}
