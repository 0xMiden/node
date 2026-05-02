use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{ParseStream, Parser};
use syn::spanned::Spanned;
use syn::{
    Attribute,
    Expr,
    ExprLit,
    Ident,
    ItemFn,
    Lit,
    LitStr,
    Meta,
    ReturnType,
    Token,
    Type,
    TypePath,
    parse_macro_input,
};

use crate::level::TelemetryLevel;
use crate::{metadata, name, target, user};

pub(crate) fn instrument(attr: TokenStream, item: TokenStream) -> TokenStream {
    let function = parse_macro_input!(item as ItemFn);

    let parser = |input: ParseStream<'_>| InstrumentArgs::parse(input);
    let instrument_args = match parser.parse(attr) {
        Ok(args) => args,
        Err(err) => return err.to_compile_error().into(),
    };

    expand_instrument(instrument_args, function).into()
}

#[derive(Debug)]
struct InstrumentArgs {
    tracing_args: proc_macro2::TokenStream,
    target: String,
    name: String,
    level: TelemetryLevel,
    user: bool,
    record_errors: bool,
}

impl InstrumentArgs {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        if input.is_empty() {
            return Err(syn::Error::new(
                input.span(),
                format!("`target` is required; expected one of: {}", target::allowed_targets()),
            ));
        }

        let target_expr = input.parse::<Expr>()?;
        let target_span = target_expr.span();
        let target = target::parse(&target_expr)?;

        parse_comma(input, "`name` is required and must be a string literal")?;
        let name_expr = input.parse::<Expr>()?;
        let name = name::parse(&name_expr)?;
        let name_literal = LitStr::new(&name, name_expr.span());

        parse_comma(input, "`level` is required")?;
        let level_expr = input.parse::<Expr>()?;
        let level = TelemetryLevel::parse(&level_expr)?;
        let level_literal = LitStr::new(level.as_str(), level_expr.span());
        let target_literal = LitStr::new(&target, target_span);

        let options = parse_options(input)?;

        Ok(Self {
            tracing_args: quote! {
                skip_all,
                target = #target_literal,
                name = #name_literal,
                level = #level_literal,
                fields(
                    miden.user.fields = ::miden_node_tracing::__private::tracing::field::Empty,
                    miden.user = ::miden_node_tracing::__private::tracing::field::Empty,
                    miden.error = ::miden_node_tracing::__private::tracing::field::Empty
                )
            },
            target,
            name,
            level,
            user: options.user,
            record_errors: options.record_errors,
        })
    }
}

#[derive(Debug, Default)]
struct InstrumentOptions {
    user: bool,
    record_errors: bool,
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

fn parse_options(input: ParseStream<'_>) -> syn::Result<InstrumentOptions> {
    let mut options = InstrumentOptions::default();

    while !input.is_empty() {
        input.parse::<Token![,]>()?;
        if input.is_empty() {
            break;
        }

        if user::try_parse_marker(input)? {
            if options.user {
                return Err(syn::Error::new(input.span(), "`user` may only be specified once"));
            }
            options.user = true;
            continue;
        }

        let ident = input.parse::<Ident>()?;
        if ident != "err" {
            return Err(syn::Error::new_spanned(
                ident,
                "only optional `user` and `err` markers are supported after `level`",
            ));
        }
        if options.record_errors {
            return Err(syn::Error::new_spanned(ident, "`err` may only be specified once"));
        }
        options.record_errors = true;
    }

    Ok(options)
}

fn expand_instrument(
    instrument_args: InstrumentArgs,
    function: ItemFn,
) -> proc_macro2::TokenStream {
    let attrs = function.attrs;
    let vis = function.vis;
    let sig = function.sig;
    let records_returned_errors = instrument_args.record_errors || returns_result(&sig.output);
    let block = function.block;
    let description =
        doc_description(&attrs).map(|description| LitStr::new(&description, sig.ident.span()));
    let target = LitStr::new(&instrument_args.target, proc_macro2::Span::call_site());
    let name = LitStr::new(&instrument_args.name, sig.ident.span());
    let level = instrument_args.level;
    let level_name = LitStr::new(level.tracing_name(), proc_macro2::Span::call_site());
    let tracing_args = instrument_args.tracing_args;
    let submit_metadata = metadata::submit_span_metadata(
        &target,
        level,
        &name,
        description.as_ref(),
        instrument_args.user,
    );
    let mark_user_span = instrument_args
        .user
        .then(|| quote! { ::miden_node_tracing::Span::current().__mark_user_facing(); });
    let record_error = records_returned_errors.then(|| {
        quote! {
            if let ::core::result::Result::Err(ref __miden_node_tracing_error) =
                __miden_node_tracing_result
            {
                ::miden_node_tracing::Span::current().__record_error(__miden_node_tracing_error);
            }
        }
    });
    let body = if sig.asyncness.is_some() {
        quote! {{
            #submit_metadata
            ::miden_node_tracing::Span::current().__record_metadata(#target, #level_name);
            #mark_user_span
            let __miden_node_tracing_result =
                ::miden_node_tracing::__private::track_current_span(async #block).await;
            #record_error
            __miden_node_tracing_result
        }}
    } else {
        quote! {{
            #submit_metadata
            let __miden_node_tracing_active_span =
                ::miden_node_tracing::__private::enter_current_span();
            ::miden_node_tracing::Span::current().__record_metadata(#target, #level_name);
            #mark_user_span
            let __miden_node_tracing_result = (|| #block)();
            #record_error
            drop(__miden_node_tracing_active_span);
            __miden_node_tracing_result
        }}
    };

    quote! {
        #(#attrs)*
        #[::miden_node_tracing::__private::tracing::instrument(#tracing_args)]
        #vis #sig #body
    }
}

fn returns_result(output: &ReturnType) -> bool {
    let ReturnType::Type(_, ty) = output else {
        return false;
    };
    let Type::Path(TypePath { qself: None, path }) = ty.as_ref() else {
        return false;
    };

    path.segments.last().is_some_and(|segment| segment.ident == "Result")
}

fn doc_description(attrs: &[Attribute]) -> Option<String> {
    let lines = attrs
        .iter()
        .filter_map(|attr| {
            let Meta::NameValue(meta) = &attr.meta else {
                return None;
            };
            if !attr.path().is_ident("doc") {
                return None;
            }
            let Expr::Lit(ExprLit { lit: Lit::Str(line), .. }) = &meta.value else {
                return None;
            };

            Some(clean_doc_line(&line.value()))
        })
        .collect::<Vec<_>>();

    trim_doc_lines(&lines).map(|lines| lines.join("\n"))
}

fn clean_doc_line(line: &str) -> String {
    line.strip_prefix(' ').unwrap_or(line).trim_end().to_owned()
}

fn trim_doc_lines(lines: &[String]) -> Option<&[String]> {
    let start = lines.iter().position(|line| !line.is_empty())?;
    let end = lines.iter().rposition(|line| !line.is_empty())? + 1;

    Some(&lines[start..end])
}

#[cfg(test)]
mod tests {
    use quote::quote;
    use syn::parse::Parser;

    use super::{InstrumentArgs, doc_description};

    fn parse_args(tokens: proc_macro2::TokenStream) -> syn::Result<InstrumentArgs> {
        (|input: syn::parse::ParseStream<'_>| InstrumentArgs::parse(input)).parse2(tokens)
    }

    #[test]
    fn requires_target() {
        let err = parse_args(quote!()).unwrap_err();

        assert!(err.to_string().contains("`target` is required"));
    }

    #[test]
    fn requires_name() {
        let err = parse_args(quote!(rpc)).unwrap_err();

        assert!(err.to_string().contains("`name` is required"));
    }

    #[test]
    fn requires_level() {
        let err = parse_args(quote!(rpc, "test")).unwrap_err();

        assert!(err.to_string().contains("`level` is required"));
    }

    #[test]
    fn rewrites_allowed_target_to_literal() {
        let args = parse_args(quote!(store::database, "test", info))
            .unwrap()
            .tracing_args
            .to_string();

        assert!(args.contains("skip_all"));
        assert!(args.contains("target = \"store::database\""));
        assert!(args.contains("name = \"test\""));
        assert!(args.contains("level = \"info\""));
    }

    #[test]
    fn parses_level_metadata() {
        let args = parse_args(quote!(store::database, "test", debug)).unwrap();

        assert_eq!(args.level, crate::level::TelemetryLevel::Debug);
        assert!(args.tracing_args.to_string().contains("level = \"debug\""));
    }

    #[test]
    fn parses_user_marker() {
        let args = parse_args(quote!(rpc, "test", info, user)).unwrap();

        assert!(args.user);
        assert!(args.tracing_args.to_string().contains("miden"));
    }

    #[test]
    fn parses_err_marker() {
        let args = parse_args(quote!(rpc, "test", info, err)).unwrap();

        assert!(args.record_errors);
    }

    #[test]
    fn parses_user_and_err_markers() {
        let args = parse_args(quote!(rpc, "test", info, err, user)).unwrap();

        assert!(args.user);
        assert!(args.record_errors);
    }

    #[test]
    fn rejects_user_value() {
        let err = parse_args(quote!(rpc, "test", info, user = true)).unwrap_err();

        assert!(err.to_string().contains("`user` is a bare marker"));
    }

    #[test]
    fn rejects_duplicate_err_marker() {
        let err = parse_args(quote!(rpc, "test", info, err, err)).unwrap_err();

        assert!(err.to_string().contains("`err` may only be specified once"));
    }

    #[test]
    fn rejects_string_level_and_path_name() {
        let level_err = parse_args(quote!(store::database, "test", "debug")).unwrap_err();
        let name_err = parse_args(quote!(store::database, test, debug)).unwrap_err();

        assert!(level_err.to_string().contains("`level` must be one of"));
        assert!(name_err.to_string().contains("`name` must be a string literal"));
    }

    #[test]
    fn rejects_named_syntax() {
        let err = parse_args(quote!(target = rpc, name = "test", level = info)).unwrap_err();

        assert!(err.to_string().contains("`target` must be an allowed target path"));
    }

    #[test]
    fn extracts_doc_comments_as_description() {
        let function: syn::ItemFn = syn::parse_quote! {
            /// First line.
            ///
            /// Second line.
            fn documented() {}
        };

        assert_eq!(
            doc_description(&function.attrs).as_deref(),
            Some("First line.\n\nSecond line.")
        );
    }
}
