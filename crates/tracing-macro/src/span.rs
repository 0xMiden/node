use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{Expr, Ident, LitStr, Token, parse_macro_input};

use crate::level::TelemetryLevel;
use crate::{metadata, name, target, user};

pub(crate) fn trace_span(input: TokenStream) -> TokenStream {
    expand_span(input, "trace_span", TelemetryLevel::Trace)
}

pub(crate) fn debug_span(input: TokenStream) -> TokenStream {
    expand_span(input, "debug_span", TelemetryLevel::Debug)
}

pub(crate) fn info_span(input: TokenStream) -> TokenStream {
    expand_span(input, "info_span", TelemetryLevel::Info)
}

pub(crate) fn warn_span(input: TokenStream) -> TokenStream {
    expand_span(input, "warn_span", TelemetryLevel::Warn)
}

pub(crate) fn error_span(input: TokenStream) -> TokenStream {
    expand_span(input, "error_span", TelemetryLevel::Error)
}

fn expand_span(input: TokenStream, macro_name: &str, level: TelemetryLevel) -> TokenStream {
    let args = parse_macro_input!(input as SpanArgs);
    let macro_name = Ident::new(macro_name, proc_macro2::Span::call_site());
    let target = LitStr::new(&args.target, args.target_span);
    let name = args.name;
    let level_name = LitStr::new(level.tracing_name(), proc_macro2::Span::call_site());
    let submit_metadata = metadata::submit_span_metadata(&target, level, &name, None, args.user);
    let mark_user_span =
        args.user.then(|| quote! { __miden_node_tracing_span.__mark_user_facing(); });

    quote! {
        {
            #submit_metadata
            let __miden_node_tracing_span = ::miden_node_tracing::Span::__from_tracing_span(
                ::miden_node_tracing::__private::tracing::#macro_name!(
                    target: #target,
                    #name,
                    miden.user.fields = ::miden_node_tracing::__private::tracing::field::Empty,
                    miden.user = ::miden_node_tracing::__private::tracing::field::Empty,
                    miden.error = ::miden_node_tracing::__private::tracing::field::Empty
                )
            );
            __miden_node_tracing_span.__record_metadata(#target, #level_name);
            #mark_user_span
            __miden_node_tracing_span
        }
    }
    .into()
}

struct SpanArgs {
    target: String,
    target_span: proc_macro2::Span,
    name: LitStr,
    user: bool,
}

impl Parse for SpanArgs {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        if input.is_empty() {
            return Err(syn::Error::new(
                input.span(),
                "`target` is required and must be the first argument",
            ));
        }

        let target_expr = input.parse::<Expr>()?;
        let target_span = target_expr.span();
        let target = target::parse(&target_expr)?;

        parse_comma(input, "`name` is required and must be a string literal")?;
        let name = parse_name(input)?;
        let user = parse_optional_user(input)?;

        Ok(Self { target, target_span, name, user })
    }
}

fn parse_name(input: ParseStream<'_>) -> syn::Result<LitStr> {
    let expr = input.parse::<Expr>()?;
    let span = expr.span();
    let span_name = name::parse(&expr)?;

    Ok(LitStr::new(&span_name, span))
}

fn parse_comma(input: ParseStream<'_>, missing_message: &str) -> syn::Result<()> {
    if input.is_empty() {
        return Err(syn::Error::new(input.span(), missing_message));
    }

    input.parse::<Token![,]>()?;
    if input.is_empty() {
        return Err(syn::Error::new(input.span(), missing_message));
    }

    Ok(())
}

fn parse_optional_user(input: ParseStream<'_>) -> syn::Result<bool> {
    if input.is_empty() {
        return Ok(false);
    }

    input.parse::<Token![,]>()?;
    if input.is_empty() {
        return Ok(false);
    }

    let user = user::try_parse_marker(input)?;
    if !user {
        let rest = input.parse::<proc_macro2::TokenStream>()?;
        return Err(syn::Error::new_spanned(
            rest,
            "built-in level span macros only support optional `user` after the span name",
        ));
    }

    if input.is_empty() {
        return Ok(true);
    }

    input.parse::<Token![,]>()?;
    if input.is_empty() {
        return Ok(true);
    }

    let rest = input.parse::<proc_macro2::TokenStream>()?;
    Err(syn::Error::new_spanned(
        rest,
        "`user` may only be specified once and must be the final argument",
    ))
}

#[cfg(test)]
mod tests {
    use quote::quote;
    use syn::parse2;

    use super::SpanArgs;

    #[test]
    fn parses_span_args() {
        let args = parse2::<SpanArgs>(quote!(store::database, "db::read")).unwrap();

        assert_eq!(args.target, "store::database");
        assert_eq!(args.name.value(), "db::read");
    }

    #[test]
    fn parses_user_marker() {
        let args = parse2::<SpanArgs>(quote!(rpc, "rpc::submit_transaction", user)).unwrap();

        assert!(args.user);
    }

    #[test]
    fn rejects_named_syntax() {
        let err = parse_err(quote!(target = rpc, "rpc::get_block"));

        assert!(err.to_string().contains("`target` must be an allowed target path"));
    }

    #[test]
    fn rejects_named_name() {
        let err = parse_err(quote!(rpc, name = "rpc::get_block"));

        assert!(err.to_string().contains("`name` must be a string literal"));
    }

    #[test]
    fn rejects_user_value() {
        let err = parse_err(quote!(rpc, "rpc::submit_transaction", user = true));

        assert!(err.to_string().contains("`user` is a bare marker"));
    }

    #[test]
    fn rejects_level_argument() {
        let err = parse_err(quote!(store::database, "db::read", info));

        assert!(err.to_string().contains("only support optional `user`"));
    }

    #[test]
    fn rejects_path_name() {
        let err = parse_err(quote!(rpc, rpc::get_block));

        assert!(err.to_string().contains("`name` must be a string literal"));
    }

    #[test]
    fn rejects_missing_target() {
        let err = parse_err(quote!());

        assert!(err.to_string().contains("`target` is required"));
    }

    #[test]
    fn rejects_missing_name() {
        let err = parse_err(quote!(rpc));

        assert!(err.to_string().contains("`name` is required"));
    }

    fn parse_err(tokens: proc_macro2::TokenStream) -> syn::Error {
        match parse2::<SpanArgs>(tokens) {
            Ok(_) => panic!("span args should fail to parse"),
            Err(err) => err,
        }
    }
}
