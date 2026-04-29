use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{Expr, Ident, LitStr, Token, parse_macro_input};

use crate::level::SpanLevel;
use crate::{metadata, name, target};

pub(crate) fn trace_span(input: TokenStream) -> TokenStream {
    expand_span(input, "trace_span", SpanLevel::Trace)
}

pub(crate) fn debug_span(input: TokenStream) -> TokenStream {
    expand_span(input, "debug_span", SpanLevel::Debug)
}

pub(crate) fn info_span(input: TokenStream) -> TokenStream {
    expand_span(input, "info_span", SpanLevel::Info)
}

pub(crate) fn warn_span(input: TokenStream) -> TokenStream {
    expand_span(input, "warn_span", SpanLevel::Warn)
}

pub(crate) fn error_span(input: TokenStream) -> TokenStream {
    expand_span(input, "error_span", SpanLevel::Error)
}

fn expand_span(input: TokenStream, macro_name: &str, level: SpanLevel) -> TokenStream {
    let args = parse_macro_input!(input as SpanArgs);
    let macro_name = Ident::new(macro_name, proc_macro2::Span::call_site());
    let target = LitStr::new(&args.target, args.target_span);
    let name = args.name;
    let submit_metadata = metadata::submit_span_metadata(&target, level, &name, None);

    quote! {
        {
            #submit_metadata
            ::miden_node_tracing::Span::new(
                ::miden_node_tracing::tracing::#macro_name!(target: #target, #name)
            )
        }
    }
    .into()
}

struct SpanArgs {
    target: String,
    target_span: proc_macro2::Span,
    name: LitStr,
}

impl Parse for SpanArgs {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let target_ident = input.parse::<Ident>()?;
        if target_ident != "target" {
            return Err(syn::Error::new_spanned(
                target_ident,
                "`target` is required and must be the first argument",
            ));
        }

        if input.peek(Token![=]) {
            input.parse::<Token![=]>()?;
        } else if input.peek(Token![:]) {
            input.parse::<Token![:]>()?;
        } else {
            return Err(syn::Error::new(input.span(), "`target` must be followed by `=` or `:`"));
        }

        let target_expr = input.parse::<Expr>()?;
        let target_span = target_expr.span();
        let target = target::parse(&target_expr)?;

        input.parse::<Token![,]>()?;
        let name = parse_name(input)?;

        if !input.is_empty() {
            let rest = input.parse::<proc_macro2::TokenStream>()?;
            return Err(syn::Error::new_spanned(
                rest,
                "`fields` is not supported; record fields with `miden_node_tracing::Span`",
            ));
        }

        Ok(Self { target, target_span, name })
    }
}

fn parse_name(input: ParseStream<'_>) -> syn::Result<LitStr> {
    let fork = input.fork();
    let expr = if fork.peek(Ident) {
        let name_ident = fork.parse::<Ident>()?;
        if name_ident == "name" && fork.peek(Token![=]) {
            input.parse::<Ident>()?;
            input.parse::<Token![=]>()?;
            input.parse::<Expr>()?
        } else {
            input.parse::<Expr>()?
        }
    } else {
        input.parse::<Expr>()?
    };
    let span = expr.span();
    let span_name = name::parse(&expr)?;

    Ok(LitStr::new(&span_name, span))
}

#[cfg(test)]
mod tests {
    use quote::quote;
    use syn::parse2;

    use super::SpanArgs;

    #[test]
    fn parses_span_args_with_equals_target() {
        let args = parse2::<SpanArgs>(quote!(target = store::database, "db::read")).unwrap();

        assert_eq!(args.target, "store::database");
        assert_eq!(args.name.value(), "db::read");
    }

    #[test]
    fn parses_span_args_with_colon_target() {
        let args =
            parse2::<SpanArgs>(quote!(target: sequencer::mempool, "mempool::select")).unwrap();

        assert_eq!(args.target, "sequencer::mempool");
        assert_eq!(args.name.value(), "mempool::select");
    }

    #[test]
    fn parses_span_args_with_named_name() {
        let args = parse2::<SpanArgs>(quote!(target = rpc, name = "rpc::get_block")).unwrap();

        assert_eq!(args.target, "rpc");
        assert_eq!(args.name.value(), "rpc::get_block");
    }

    #[test]
    fn rejects_fields() {
        let err = parse_err(quote!(target = store::database, "db::read", block.number = 1));

        assert!(err.to_string().contains("`fields` is not supported"));
    }

    #[test]
    fn rejects_path_name() {
        let err = parse_err(quote!(target = rpc, rpc::get_block));

        assert!(err.to_string().contains("`name` must be a string literal"));
    }

    #[test]
    fn rejects_missing_target() {
        let err = parse_err(quote!(db::read));

        assert!(err.to_string().contains("`target` is required"));
    }

    fn parse_err(tokens: proc_macro2::TokenStream) -> syn::Error {
        match parse2::<SpanArgs>(tokens) {
            Ok(_) => panic!("span args should fail to parse"),
            Err(err) => err,
        }
    }
}
