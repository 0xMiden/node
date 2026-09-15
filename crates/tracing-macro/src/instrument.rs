use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::visit_mut::{self, VisitMut};
use syn::{
    Block,
    Expr,
    GenericArgument,
    ItemFn,
    Lit,
    Meta,
    PathArguments,
    Result,
    ReturnType,
    Stmt,
    Type,
    TypeParamBound,
    parse_quote,
};

use crate::split_top_level_args;

pub fn instrument_result(attr: TokenStream, function: &mut ItemFn) -> Result<TokenStream> {
    let mut args = split_top_level_args(attr);
    let Some(err) = take_argument(&mut args, "err")? else {
        return Ok(quote! { #(#args),* });
    };
    let err = EventOptions::parse(err, false)?;
    let ret = take_argument(&mut args, "ret")?
        .map(|arg| EventOptions::parse(arg, true))
        .transpose()?;
    let target = argument_value(&args, "target")?.unwrap_or_else(|| parse_quote!(module_path!()));
    let error_level = err.level.unwrap_or_else(|| quote!(::miden_node_tracing::Level::ERROR));
    let ret_event = if let Some(ret) = ret {
        let level = match ret.level {
            Some(level) => level,
            None => argument_value(&args, "level")?
                .map(level_tokens)
                .transpose()?
                .unwrap_or_else(|| quote!(::miden_node_tracing::Level::INFO)),
        };
        let value = if ret.display {
            quote!(::miden_node_tracing::field::display(__miden_value))
        } else {
            quote!(::miden_node_tracing::field::debug(__miden_value))
        };
        quote! {
            if let ::core::result::Result::Ok(__miden_value) = &__miden_result {
                ::miden_node_tracing::event!(target: #target, #level, return = #value);
            }
        }
    } else {
        TokenStream::new()
    };
    let events = quote! {
        if let ::core::result::Result::Err(__miden_error) = &__miden_result {
            use ::miden_node_tracing::__private::AsDynError as _;
            ::miden_node_tracing::event!(
                name: "exception",
                target: #target,
                #error_level,
                error = __miden_error.as_dyn_error()
            );
        }
        #ret_event
        __miden_result
    };

    let output = match &function.sig.output {
        ReturnType::Type(_, ty) => Some(ty.as_ref()),
        ReturnType::Default => None,
    };
    if function.sig.asyncness.is_some() {
        wrap_result(&mut function.block, true, output, &events);
    } else if let Some(block) = returned_async_block(&mut function.block) {
        // Keep the future visible to upstream instrumentation so it enters the span on each poll.
        let output = output.and_then(future_output);
        wrap_result(block, true, output.as_ref(), &events);
    } else {
        wrap_result(&mut function.block, false, output, &events);
    }

    Ok(quote! { #(#args),* })
}

fn wrap_result(block: &mut Block, is_async: bool, output: Option<&Type>, events: &TokenStream) {
    let return_type = if let Some(output) = output {
        let mut output = output.clone();
        EraseImplTrait.visit_type_mut(&mut output);
        // Give return expressions and `?` the declared type before error method resolution.
        quote! {
            #[allow(unreachable_code, clippy::diverging_sub_expression, clippy::empty_loop)]
            if false {
                let __miden_return: #output = loop {};
                return __miden_return;
            }
        }
    } else {
        TokenStream::new()
    };
    let body = quote!({ #return_type #block });
    let result = if is_async {
        quote!(async move #body.await)
    } else {
        quote!((move || #body)())
    };
    *block = parse_quote!({
        #[allow(clippy::redundant_closure_call)]
        let __miden_result = #result;
        #events
    });
}

struct EraseImplTrait;

impl VisitMut for EraseImplTrait {
    fn visit_type_mut(&mut self, ty: &mut Type) {
        if matches!(ty, Type::ImplTrait(_)) {
            *ty = parse_quote!(_);
        } else {
            visit_mut::visit_type_mut(self, ty);
        }
    }
}

fn future_output(ty: &Type) -> Option<Type> {
    let Type::ImplTrait(ty) = ty else {
        return Some(parse_quote!(<#ty as ::core::future::Future>::Output));
    };
    ty.bounds.iter().find_map(|bound| {
        let TypeParamBound::Trait(bound) = bound else {
            return None;
        };
        let segment = bound.path.segments.last()?;
        let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
            return None;
        };
        arguments.args.iter().find_map(|argument| match argument {
            GenericArgument::AssocType(binding) if binding.ident == "Output" => {
                Some(binding.ty.clone())
            },
            // Miden's future trait declares its output as a type argument.
            GenericArgument::Type(output) if segment.ident == "FutureMaybeSend" => {
                Some(output.clone())
            },
            _ => None,
        })
    })
}

fn returned_async_block(block: &mut Block) -> Option<&mut Block> {
    let Stmt::Expr(expr, _) = block.stmts.last_mut()? else {
        return None;
    };
    let expr = match expr {
        Expr::Call(call) => {
            let Expr::Path(path) = call.func.as_ref() else {
                return None;
            };
            let mut segments = path.path.segments.iter().rev();
            if segments.next()?.ident != "pin" || segments.next()?.ident != "Box" {
                return None;
            }
            call.args.first_mut()?
        },
        expr => expr,
    };
    match expr {
        Expr::Async(expr) => Some(&mut expr.block),
        _ => None,
    }
}

fn take_argument(args: &mut Vec<TokenStream>, name: &str) -> Result<Option<Meta>> {
    let mut found = None;
    let mut remaining = Vec::new();
    for arg in args.drain(..) {
        if starts_with(&arg, name) {
            if found.is_some() {
                return Err(syn::Error::new_spanned(arg, format!("duplicate `{name}` argument")));
            }
            found = Some(syn::parse2(arg)?);
        } else {
            remaining.push(arg);
        }
    }
    *args = remaining;
    Ok(found)
}

fn starts_with(arg: &TokenStream, name: &str) -> bool {
    matches!(arg.clone().into_iter().next(), Some(proc_macro2::TokenTree::Ident(ident)) if ident == name)
}

fn argument_value(args: &[TokenStream], name: &str) -> Result<Option<Expr>> {
    args.iter()
        .find(|arg| starts_with(arg, name))
        .map(|arg| syn::parse2::<syn::MetaNameValue>(arg.clone()).map(|arg| arg.value))
        .transpose()
}

#[derive(Default)]
struct EventOptions {
    level: Option<TokenStream>,
    display: bool,
}

impl EventOptions {
    fn parse(arg: Meta, allow_formatter: bool) -> Result<Self> {
        let mut options = Self::default();
        let list = match arg {
            Meta::Path(_) => return Ok(options),
            Meta::List(list) => list,
            arg @ Meta::NameValue(_) => {
                return Err(syn::Error::new_spanned(arg, "expected `err` or `ret` options"));
            },
        };
        let mut formatter = false;
        for arg in split_top_level_args(list.tokens) {
            match syn::parse2::<Meta>(arg.clone())? {
                Meta::NameValue(value) if value.path.is_ident("level") => {
                    if options.level.is_some() {
                        return Err(syn::Error::new_spanned(arg, "duplicate `level` argument"));
                    }
                    options.level = Some(level_tokens(value.value)?);
                },
                Meta::Path(path) if path.is_ident("Debug") || path.is_ident("Display") => {
                    if !allow_formatter {
                        return Err(syn::Error::new_spanned(
                            arg,
                            "`err` formatters are not supported; errors are recorded as typed values",
                        ));
                    }
                    if formatter {
                        return Err(syn::Error::new_spanned(arg, "duplicate formatter"));
                    }
                    formatter = true;
                    options.display = path.is_ident("Display");
                },
                _ => return Err(syn::Error::new_spanned(arg, "unsupported event option")),
            }
        }
        Ok(options)
    }
}

fn level_tokens(value: Expr) -> Result<TokenStream> {
    let name = match &value {
        Expr::Lit(expr) => match &expr.lit {
            Lit::Str(value) => value.value().to_ascii_lowercase(),
            Lit::Int(value) => value.base10_digits().to_owned(),
            _ => String::new(),
        },
        Expr::Path(_) => return Ok(value.into_token_stream()),
        _ => String::new(),
    };
    let level = match name.as_str() {
        "trace" | "1" => quote!(TRACE),
        "debug" | "2" => quote!(DEBUG),
        "info" | "3" => quote!(INFO),
        "warn" | "4" => quote!(WARN),
        "error" | "5" => quote!(ERROR),
        _ => {
            return Err(syn::Error::new_spanned(value, "expected a tracing level or a number 1-5"));
        },
    };
    Ok(quote!(::miden_node_tracing::Level::#level))
}
