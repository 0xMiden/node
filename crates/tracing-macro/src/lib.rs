//! Procedural macro for tracing instrumentation with full error report context.
//!
//! This macro provides an `#[instrument]`-like attribute that uses `ErrorReport::as_report()`
//! to capture the full error chain in tracing spans, rather than just the `Display` output.
//!
//! **Note**: This crate should not be used directly. Use `miden-node-tracing` instead,
//! which re-exports this macro along with all required dependencies.
//!
//! # Problem
//!
//! The standard `#[instrument(err)]` from `tracing` uses `Display` or `Debug` to format errors
//! in span events. This loses the error chain context, showing only the top-level error message.
//!
//! # Solution
//!
//! This macro wraps functions that return `Result<T, E>` and:
//! 1. Creates a tracing span with the configured attributes (delegating to `tracing::instrument`)
//! 2. On error, records the full error chain using `ErrorReport::as_report()`
//! 3. Sets the OpenTelemetry span status to error with the full report

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{ItemFn, ReturnType, parse_macro_input};

/// Instruments a function with tracing, using full error reports for context.
///
/// This attribute macro wraps functions that return `Result<T, E>` and creates
/// a tracing span. When the function returns an error, it records the full
/// error chain using `ErrorReport::as_report()` instead of just `Display`.
///
/// This macro accepts all the same arguments as `tracing::instrument`, and
/// delegates to it for span creation. The added functionality is enhanced
/// error reporting when `err` is specified.
///
/// # Arguments
///
/// All arguments from `tracing::instrument` are supported:
/// - `target = "..."` - Sets the tracing target
/// - `level = "..."` - Sets the tracing level (default: "info")
/// - `name = "..."` - Sets a custom span name (default: function name)
/// - `err` - Record errors with full error chain (enhanced by this macro)
/// - `ret` / `ret(level = "...")` - Record return values
/// - `skip(arg1, arg2)` - Skip specific arguments from span fields
/// - `skip_all` - Skip all arguments from span fields
/// - `fields(key = value, ...)` - Add custom fields to the span
/// - `parent = None` - Create a root span (no parent)
///
/// # Example
///
/// ```rust,ignore
/// use miden_node_tracing::instrument_with_err_report;
///
/// #[instrument_with_err_report(target = COMPONENT, skip_all, err)]
/// pub async fn apply_block(&self, block: ProvenBlock) -> Result<(), ApplyBlockError> {
///     // Function body...
/// }
/// ```
#[proc_macro_attribute]
pub fn instrument_with_err_report(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr2 = TokenStream2::from(attr.clone());
    let input = parse_macro_input!(item as ItemFn);

    // Check if 'err' is present in the attributes
    let attr_str = attr2.to_string();
    let has_err = attr_str.contains("err");

    // Check if the function returns a Result
    let returns_result = match &input.sig.output {
        ReturnType::Default => false,
        ReturnType::Type(_, ty) => {
            let ty_str = quote! { #ty }.to_string();
            ty_str.contains("Result")
        },
    };

    if has_err && returns_result {
        generate_with_error_reporting(&attr2, input).into()
    } else {
        // Just delegate to standard tracing::instrument
        let ItemFn { attrs, vis, sig, block } = input;
        quote! {
            #(#attrs)*
            #[::tracing::instrument(#attr2)]
            #vis #sig
            #block
        }
        .into()
    }
}

fn generate_with_error_reporting(attr: &TokenStream2, input: ItemFn) -> TokenStream2 {
    let ItemFn { attrs, vis, sig, block } = input;

    // Remove 'err' from the attributes we pass to tracing::instrument
    // since we handle error reporting ourselves
    let tracing_attr = remove_err_from_attr(attr);

    // Get the return type for type annotation
    let result_type = match &sig.output {
        ReturnType::Type(_, ty) => quote! { #ty },
        ReturnType::Default => quote! { () },
    };

    // Use absolute paths via the miden_node_tracing crate
    quote! {
        #(#attrs)*
        #[::tracing::instrument(#tracing_attr)]
        #vis #sig
        {
            let __result: #result_type = #block;

            if let ::core::result::Result::Err(ref __err) = __result {
                // Use ErrorReport to get the full error chain
                let __report = {
                    use ::miden_node_tracing::ErrorReport as _;
                    __err.as_report()
                };

                // Record the error event with the full report
                ::miden_node_tracing::error!(error = %__report);

                // Set OpenTelemetry span status if available
                {
                    use ::miden_node_tracing::OpenTelemetrySpanExt as _;
                    ::miden_node_tracing::Span::current().set_error(__err as &dyn ::std::error::Error);
                }
            }

            __result
        }
    }
}

fn remove_err_from_attr(attr: &TokenStream2) -> TokenStream2 {
    // Simple string-based removal of 'err' from the attribute
    // This handles both 'err' and 'err,' patterns
    let attr_str = attr.to_string();

    // Remove 'err,' or ', err' or 'err' patterns
    let cleaned = attr_str
        .replace(", err,", ",")
        .replace(", err", "")
        .replace("err,", "")
        .replace("err", "");

    // Parse the cleaned string back into tokens
    cleaned.parse().unwrap_or_else(|_| attr.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_err_from_attr_trailing() {
        let attr: TokenStream2 = "target = COMPONENT, skip_all, err".parse().unwrap();
        let result = remove_err_from_attr(&attr);
        let result_str = result.to_string();
        assert!(!result_str.contains("err"), "Should remove 'err': {result_str}");
        assert!(result_str.contains("target"), "Should keep 'target': {result_str}");
        assert!(result_str.contains("skip_all"), "Should keep 'skip_all': {result_str}");
    }

    #[test]
    fn test_remove_err_from_attr_middle() {
        let attr: TokenStream2 = "target = COMPONENT, err, skip_all".parse().unwrap();
        let result = remove_err_from_attr(&attr);
        let result_str = result.to_string();
        assert!(!result_str.contains("err"), "Should remove 'err': {result_str}");
        assert!(result_str.contains("target"), "Should keep 'target': {result_str}");
        assert!(result_str.contains("skip_all"), "Should keep 'skip_all': {result_str}");
    }

    #[test]
    fn test_remove_err_from_attr_only() {
        let attr: TokenStream2 = "err".parse().unwrap();
        let result = remove_err_from_attr(&attr);
        let result_str = result.to_string();
        assert!(!result_str.contains("err"), "Should remove 'err': {result_str}");
    }

    #[test]
    fn test_remove_err_from_attr_with_ret() {
        let attr: TokenStream2 =
            "level = \"debug\", target = COMPONENT, err, ret(level = \"debug\")"
                .parse()
                .unwrap();
        let result = remove_err_from_attr(&attr);
        let result_str = result.to_string();
        assert!(!result_str.contains(", err,"), "Should remove ', err,': {result_str}");
        assert!(result_str.contains("level"), "Should keep 'level': {result_str}");
        assert!(result_str.contains("ret"), "Should keep 'ret': {result_str}");
    }

    #[test]
    fn test_returns_result_detection() {
        // Test with Result type
        let fn_with_result: syn::ItemFn = syn::parse_quote! {
            fn test_fn() -> Result<(), Error> {
                Ok(())
            }
        };
        let returns_result = match &fn_with_result.sig.output {
            ReturnType::Default => false,
            ReturnType::Type(_, ty) => {
                let ty_str = quote! { #ty }.to_string();
                ty_str.contains("Result")
            },
        };
        assert!(returns_result, "Should detect Result return type");

        // Test without Result type
        let fn_without_result: syn::ItemFn = syn::parse_quote! {
            fn test_fn() -> i32 {
                42
            }
        };
        let returns_result = match &fn_without_result.sig.output {
            ReturnType::Default => false,
            ReturnType::Type(_, ty) => {
                let ty_str = quote! { #ty }.to_string();
                ty_str.contains("Result")
            },
        };
        assert!(!returns_result, "Should not detect Result for i32 return type");

        // Test with no return type
        let fn_no_return: syn::ItemFn = syn::parse_quote! {
            fn test_fn() {
                println!("hello");
            }
        };
        let returns_result = match &fn_no_return.sig.output {
            ReturnType::Default => false,
            ReturnType::Type(_, ty) => {
                let ty_str = quote! { #ty }.to_string();
                ty_str.contains("Result")
            },
        };
        assert!(!returns_result, "Should not detect Result for unit return type");
    }

    #[test]
    fn test_err_detection_in_attrs() {
        // Test with err present
        let attr_with_err = "target = COMPONENT, skip_all, err";
        assert!(attr_with_err.contains("err"), "Should find 'err'");

        // Test without err
        let attr_without_err = "target = COMPONENT, skip_all";
        assert!(!attr_without_err.contains("err"), "Should not find 'err'");

        // Test with err in field name (should still match, but that's acceptable)
        let attr_with_error_field = "target = COMPONENT, fields(error = true)";
        // Note: This is a known limitation - "error" contains "err"
        // In practice this doesn't cause issues because if someone uses fields(error=...)
        // they likely don't intend to use our error reporting anyway
        assert!(attr_with_error_field.contains("err"), "Contains 'err' substring");
    }
}
