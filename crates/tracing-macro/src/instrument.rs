use proc_macro::TokenStream;
use quote::quote;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{Attribute, Expr, ExprLit, ItemFn, Lit, LitStr, Meta, Token, parse_macro_input};

use crate::level::SpanLevel;
use crate::{metadata, name, target};

pub(crate) fn instrument(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr with Punctuated::<Meta, Token![,]>::parse_terminated);
    let function = parse_macro_input!(item as ItemFn);

    let instrument_args = match InstrumentArgs::parse(args) {
        Ok(args) => args,
        Err(err) => return err.to_compile_error().into(),
    };

    expand_instrument(instrument_args, function).into()
}

#[derive(Debug)]
struct InstrumentArgs {
    tracing_args: proc_macro2::TokenStream,
    target: String,
    name: Option<String>,
    level: SpanLevel,
}

impl InstrumentArgs {
    fn parse(args: Punctuated<Meta, Token![,]>) -> syn::Result<Self> {
        let mut target = None;
        let mut name = None;
        let mut level = SpanLevel::Info;
        let mut level_seen = false;
        let mut tracing_args = Vec::new();

        for arg in args {
            let ident = arg.path().get_ident().map(ToString::to_string);

            match ident.as_deref() {
                Some("name") => {
                    let meta = name_value_arg(arg, "`name`")?;
                    if name.is_some() {
                        return Err(syn::Error::new_spanned(
                            meta,
                            "`name` may only be specified once",
                        ));
                    }
                    let value = name::parse(&meta.value)?;
                    let value_literal = LitStr::new(&value, meta.value.span());

                    name = Some(value);
                    tracing_args.push(quote! { name = #value_literal });
                },
                Some("level") => {
                    let meta = name_value_arg(arg, "`level`")?;
                    if level_seen {
                        return Err(syn::Error::new_spanned(
                            meta,
                            "`level` may only be specified once",
                        ));
                    }
                    level_seen = true;
                    level = SpanLevel::parse(&meta.value)?;
                    let value = LitStr::new(level.as_str(), meta.value.span());

                    tracing_args.push(quote! { level = #value });
                },
                Some("target") => {
                    let meta = name_value_arg(arg, "`target`")?;
                    if target.is_some() {
                        return Err(syn::Error::new_spanned(
                            meta,
                            "`target` may only be specified once",
                        ));
                    }

                    let value = target::parse(&meta.value)?;
                    let value_literal = LitStr::new(&value, meta.value.span());

                    target = Some(value);
                    tracing_args.push(quote! { target = #value_literal });
                },
                Some("skip_all") => {
                    Err(syn::Error::new_spanned(arg, "`skip_all` is always applied by this macro"))?
                },
                Some("skip") => Err(syn::Error::new_spanned(
                    arg,
                    "`skip` is not supported; this macro always skips all arguments",
                ))?,
                Some("fields") => Err(syn::Error::new_spanned(
                    arg,
                    "`fields` is not supported; record fields with `miden_node_tracing::Span`",
                ))?,
                Some("err") => Err(syn::Error::new_spanned(
                    arg,
                    "`err` is not supported; this macro records returned errors with `Span::record_error`",
                ))?,
                Some(_) => Err(syn::Error::new_spanned(
                    arg,
                    "unsupported instrument argument; only `name`, `target`, and `level` are supported",
                ))?,
                None => Err(syn::Error::new_spanned(arg, "unsupported instrument argument"))?,
            }
        }

        let target = target.ok_or_else(|| {
            syn::Error::new(
                proc_macro2::Span::call_site(),
                format!("`target` is required; expected one of: {}", target::allowed_targets()),
            )
        })?;

        tracing_args.insert(0, quote! { skip_all });

        Ok(Self {
            tracing_args: quote! { #(#tracing_args),* },
            target,
            name,
            level,
        })
    }
}

fn name_value_arg(arg: Meta, name: &str) -> syn::Result<syn::MetaNameValue> {
    match arg {
        Meta::NameValue(meta) => Ok(meta),
        _ => Err(syn::Error::new_spanned(
            arg,
            format!("{name} must be specified as a name-value argument"),
        )),
    }
}

fn expand_instrument(
    instrument_args: InstrumentArgs,
    function: ItemFn,
) -> proc_macro2::TokenStream {
    let attrs = function.attrs;
    let vis = function.vis;
    let sig = function.sig;
    let block = function.block;
    let description =
        doc_description(&attrs).map(|description| LitStr::new(&description, sig.ident.span()));
    let target = LitStr::new(&instrument_args.target, proc_macro2::Span::call_site());
    let default_name;
    let name = if let Some(name) = &instrument_args.name {
        LitStr::new(name, sig.ident.span())
    } else {
        default_name = sig.ident.to_string();
        LitStr::new(&default_name, sig.ident.span())
    };
    let level = instrument_args.level;
    let tracing_args = instrument_args.tracing_args;
    let submit_metadata =
        metadata::submit_span_metadata(&target, level, &name, description.as_ref());
    let body = if sig.asyncness.is_some() {
        quote! {{
            #submit_metadata
            let __miden_node_tracing_result = (async #block).await;
            if let ::core::result::Result::Err(ref __miden_node_tracing_error) =
                __miden_node_tracing_result
            {
                ::miden_node_tracing::Span::current().record_error(__miden_node_tracing_error);
            }
            __miden_node_tracing_result
        }}
    } else {
        quote! {{
            #submit_metadata
            let __miden_node_tracing_result = (|| #block)();
            if let ::core::result::Result::Err(ref __miden_node_tracing_error) =
                __miden_node_tracing_result
            {
                ::miden_node_tracing::Span::current().record_error(__miden_node_tracing_error);
            }
            __miden_node_tracing_result
        }}
    };

    quote! {
        #(#attrs)*
        #[::miden_node_tracing::tracing::instrument(#tracing_args)]
        #vis #sig #body
    }
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
    use syn::punctuated::Punctuated;
    use syn::{Meta, Token};

    use super::{InstrumentArgs, doc_description};

    fn parse_args(
        tokens: proc_macro2::TokenStream,
    ) -> syn::punctuated::Punctuated<Meta, Token![,]> {
        Punctuated::<Meta, Token![,]>::parse_terminated
            .parse2(tokens)
            .expect("test args should parse")
    }

    #[test]
    fn requires_target() {
        let err = InstrumentArgs::parse(parse_args(quote!(name = "test"))).unwrap_err();

        assert!(err.to_string().contains("`target` is required"));
    }

    #[test]
    fn rewrites_allowed_target_to_literal() {
        let args =
            InstrumentArgs::parse(parse_args(quote!(target = store::database, name = "test")))
                .unwrap()
                .tracing_args
                .to_string();

        assert!(args.contains("skip_all"));
        assert!(args.contains("target = \"store::database\""));
        assert!(args.contains("name = \"test\""));
    }

    #[test]
    fn parses_level_metadata() {
        let args = InstrumentArgs::parse(parse_args(quote!(
            target = store::database,
            level = debug,
            name = "test"
        )))
        .unwrap();

        assert_eq!(args.level, crate::level::SpanLevel::Debug);
        assert!(args.tracing_args.to_string().contains("level = \"debug\""));
    }

    #[test]
    fn rejects_string_level_and_path_name() {
        let level_err =
            InstrumentArgs::parse(parse_args(quote!(target = store::database, level = "debug")))
                .unwrap_err();
        let name_err =
            InstrumentArgs::parse(parse_args(quote!(target = store::database, name = test)))
                .unwrap_err();

        assert!(level_err.to_string().contains("`level` must be one of"));
        assert!(name_err.to_string().contains("`name` must be a string literal"));
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
