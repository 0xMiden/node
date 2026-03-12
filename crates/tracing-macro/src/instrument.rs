use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::punctuated::Punctuated;
use syn::{Expr, Ident, ItemFn, LitStr, ReturnType, Token};

// #[instrument(COMPONENT: checked_name=%foo, x=%y, ret, report)]
// #[instrument(COMPONENT: checked_name=%foo, x=%y, ret, err)]
// #[instrument(COMPONENT: checked_name=%foo, x=%y)]

/// Value of a single value to track
struct Value {
    print_modifier: Option<Token![%]>,
    value: Expr,
}

/// An otel identifier, not _yet_ checked
pub(crate) struct Name {
    segments: Punctuated<Ident, Token![.]>,
}

impl Name {
    fn to_string(&self) -> String {
        self.segments.iter().map(|ident| ident.to_string()).join(".")
    }
}

/// An otel identifier, checked against the whitelist
struct CheckedName(Name);

/// An raw value, which also serves as otel identifier, checked against the whitelist
struct CheckedValue(Value);

enum Checked {
    Direct(CheckedValue),
    Alias {
        name: CheckedName,
        _equals: Option<Token![=]>,
        value: Value,
    },
}

/// Track the return value of caller
struct RetVal {}
/// Track the error, assuming it's an `std::error::Error`
struct StdErrVal {}
/// Track the error, assuming it's a `Report`
struct ReportVal {}

enum Ret {
    /// Track the return value, commonly used for integers, bool, enums - cheap ones - when used
    /// with `StdErr` or `Report`
    Value,
    /// Track the error variant
    StdErr,
}

/// Defines the component to use
enum ComponentName {
    /// Use the explicitly provided string literal
    Literal(LitStr),
    /// Use the explicitly provided identifier
    Ident(Ident),
    /// Assume there is a `COMPONENT` variable inside the current module.
    Scope,
}

enum Element {
    Track(Checked),
    Ret(Ret),
}

struct InstrumentArgs {
    component: ComponentName,
    _colon: Token![:],
    values: Punctuated<Element, Token![,]>,
}

pub fn instrument2(attr2: TokenStream2, item2: TokenStream2) -> syn::Result<TokenStream2> {
    let attr = syn::parse_macro_input!(attr2 as InstrumentArgs);
    let item = syn::parse_macro_input!(item2 as Item);

    // Check if 'err' is present in the attributes
    let attr_str = attr2.to_string();
    let has_err = attr_str.contains("err");

    // Check if the function returns a Result
    let returns_result = match &item.sig.output {
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
