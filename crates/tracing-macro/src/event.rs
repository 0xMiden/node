use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{ParseStream, Parser};
use syn::spanned::Spanned;
use syn::{Expr, Ident, LitStr, Token};

use crate::level::TelemetryLevel;
use crate::{metadata, target, user};

const MISSING_JUSTIFICATION: &str = "event macros require `justification = \"...\"`; events are \
                                    discouraged in favor of spans, so explain why this \
                                    point-in-time event is appropriate";

pub(crate) fn event(input: TokenStream) -> TokenStream {
    expand_event(input, None)
}

pub(crate) fn trace(input: TokenStream) -> TokenStream {
    expand_event(input, Some(TelemetryLevel::Trace))
}

pub(crate) fn debug(input: TokenStream) -> TokenStream {
    expand_event(input, Some(TelemetryLevel::Debug))
}

pub(crate) fn info(input: TokenStream) -> TokenStream {
    expand_event(input, Some(TelemetryLevel::Info))
}

pub(crate) fn warn(input: TokenStream) -> TokenStream {
    expand_event(input, Some(TelemetryLevel::Warn))
}

pub(crate) fn error(input: TokenStream) -> TokenStream {
    expand_event(input, Some(TelemetryLevel::Error))
}

fn expand_event(input: TokenStream, fixed_level: Option<TelemetryLevel>) -> TokenStream {
    let parser = |input: ParseStream<'_>| EventArgs::parse(input, fixed_level);
    let args = match parser.parse(input) {
        Ok(args) => args,
        Err(err) => return err.to_compile_error().into(),
    };
    let target = LitStr::new(&args.target, args.target_span);
    let level = args.level.tracing_tokens();
    let level_name = LitStr::new(args.level.tracing_name(), proc_macro2::Span::call_site());
    let message = args.message;
    let event_name = quote! { #message };
    let mark_user_event =
        args.user.then(|| quote! { __miden_node_tracing_event.__mark_user_facing(); });
    let emit_user_log_event = if args.user {
        quote! {
            Some(|__miden_node_tracing_name, __miden_node_tracing_attributes| {
                let __miden_node_tracing_fields =
                    ::miden_node_tracing::__private::format_user_attributes(
                        __miden_node_tracing_attributes
                    );
                ::miden_node_tracing::__private::tracing::event!(
                    target: #target,
                    #level,
                    miden.user.log = true,
                    message = %__miden_node_tracing_name,
                    miden.user.fields = %__miden_node_tracing_fields,
                );
            })
        }
    } else {
        quote! { None }
    };
    let submit_metadata = metadata::submit_event_metadata(&target, args.level, &message, args.user);

    quote! {
        {
            #submit_metadata
            // Use tracing's filter gate so disabled targets/levels do not pay to construct typed
            // event attributes. The returned event buffers explicit records and emits when it is
            // dropped.
            if ::miden_node_tracing::__private::tracing::event_enabled!(target: #target, #level) {
                let mut __miden_node_tracing_event =
                    ::miden_node_tracing::__private::OpenTelemetryEventRecorder::new();
                __miden_node_tracing_event.record_attribute("level", #level_name);
                __miden_node_tracing_event.record_attribute("target", #target);
                #mark_user_event
                ::miden_node_tracing::Event::__new(
                    ::miden_node_tracing::Span::current(),
                    #event_name,
                    __miden_node_tracing_event,
                    #emit_user_log_event
                )
            } else {
                ::miden_node_tracing::Event::__disabled()
            }
        }
    }
    .into()
}

struct EventArgs {
    target: String,
    target_span: proc_macro2::Span,
    level: TelemetryLevel,
    message: LitStr,
    user: bool,
}

impl EventArgs {
    fn parse(input: ParseStream<'_>, fixed_level: Option<TelemetryLevel>) -> syn::Result<Self> {
        if input.is_empty() {
            return Err(syn::Error::new(
                input.span(),
                "`target` is required and must be the first argument",
            ));
        }

        let target_expr = input.parse::<Expr>()?;
        let target_span = target_expr.span();
        let target = target::parse(&target_expr)?;

        parse_comma(input, "`message` is required")?;
        reject_event_record(input)?;
        let message = parse_message(input)?;

        let level = if let Some(fixed_level) = fixed_level {
            fixed_level
        } else {
            parse_comma(input, "`level` is required")?;
            let level_expr = input.parse::<Expr>()?;
            TelemetryLevel::parse(&level_expr)?
        };

        let user = parse_options(input, fixed_level.is_some())?;

        Ok(Self {
            target,
            target_span,
            level,
            message,
            user,
        })
    }
}

fn parse_message(input: ParseStream<'_>) -> syn::Result<LitStr> {
    if !input.peek(LitStr) {
        return Err(syn::Error::new(input.span(), "`message` must start with a string literal"));
    }

    let message = input.parse::<LitStr>()?;
    if message.value().trim().is_empty() {
        return Err(syn::Error::new_spanned(message, "`message` must not be empty"));
    }

    Ok(message)
}

fn reject_event_record(input: ParseStream<'_>) -> syn::Result<()> {
    if input.peek(Ident) {
        let ident = input.fork().parse::<Ident>()?;
        if ident == "field" || ident == "object" {
            return Err(syn::Error::new_spanned(
                ident,
                "`field(...)` and `object(...)` are not supported; record attributes on the \
                 returned `Event`",
            ));
        }
    }

    Ok(())
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

fn parse_options(input: ParseStream<'_>, built_in_level: bool) -> syn::Result<bool> {
    if input.is_empty() {
        return Err(syn::Error::new(input.span(), MISSING_JUSTIFICATION));
    }

    input.parse::<Token![,]>()?;
    if input.is_empty() {
        return Err(syn::Error::new(input.span(), MISSING_JUSTIFICATION));
    }

    let user = user::try_parse_marker(input)?;
    if user {
        if input.is_empty() {
            return Err(syn::Error::new(input.span(), MISSING_JUSTIFICATION));
        }
        input.parse::<Token![,]>()?;
        if input.is_empty() {
            return Err(syn::Error::new(input.span(), MISSING_JUSTIFICATION));
        }
    }

    parse_justification(input, built_in_level)?;

    Ok(user)
}

fn parse_justification(input: ParseStream<'_>, built_in_level: bool) -> syn::Result<()> {
    if !input.peek(Ident) {
        let rest = input.parse::<proc_macro2::TokenStream>()?;
        return Err(syn::Error::new_spanned(rest, MISSING_JUSTIFICATION));
    }

    let ident = input.parse::<Ident>()?;
    if ident == "user" {
        return Err(syn::Error::new_spanned(
            ident,
            "`user` may only be specified once and must appear before `justification`",
        ));
    }
    if ident != "justification" {
        let message = if built_in_level {
            "built-in level event macros only support optional `user` followed by required \
             `justification = \"...\"`; do not pass a level to `trace!`, `debug!`, `info!`, \
             `warn!`, or `error!`"
        } else {
            "only optional `user` followed by required `justification = \"...\"` is supported \
             after `level`"
        };
        return Err(syn::Error::new_spanned(ident, message));
    }

    if !input.peek(Token![=]) {
        return Err(syn::Error::new_spanned(ident, "`justification` must be followed by `=`"));
    }
    input.parse::<Token![=]>()?;

    if !input.peek(LitStr) {
        return Err(syn::Error::new(
            input.span(),
            "`justification` must be a non-empty string literal",
        ));
    }
    let justification = input.parse::<LitStr>()?;
    if justification.value().trim().is_empty() {
        return Err(syn::Error::new_spanned(justification, "`justification` must not be empty"));
    }

    if input.is_empty() {
        return Ok(());
    }

    input.parse::<Token![,]>()?;
    if input.is_empty() {
        return Ok(());
    }

    let rest = input.parse::<proc_macro2::TokenStream>()?;
    Err(syn::Error::new_spanned(
        rest,
        "`justification` must be the final event macro argument",
    ))
}

#[cfg(test)]
mod tests {
    use quote::quote;
    use syn::parse::Parser;

    use super::EventArgs;
    use crate::level::TelemetryLevel;

    fn parse_args(
        tokens: proc_macro2::TokenStream,
        fixed_level: Option<TelemetryLevel>,
    ) -> syn::Result<EventArgs> {
        (|input: syn::parse::ParseStream<'_>| EventArgs::parse(input, fixed_level)).parse2(tokens)
    }

    fn parse_err(
        tokens: proc_macro2::TokenStream,
        fixed_level: Option<TelemetryLevel>,
    ) -> syn::Error {
        let Err(err) = parse_args(tokens, fixed_level) else {
            panic!("event args should fail to parse");
        };
        err
    }

    #[test]
    fn parses_level_event_args() {
        let args = parse_args(
            quote!(rpc, "accepted block", user, justification = "records a user milestone"),
            Some(TelemetryLevel::Info),
        )
        .unwrap();

        assert_eq!(args.target, "rpc");
        assert_eq!(args.level, TelemetryLevel::Info);
        assert_eq!(args.message.value(), "accepted block");
        assert!(args.user);
    }

    #[test]
    fn parses_event_macro_level() {
        let args = parse_args(
            quote!(store::database, "loaded block", debug, justification = "captures a cache miss"),
            None,
        )
        .unwrap();

        assert_eq!(args.target, "store::database");
        assert_eq!(args.level, TelemetryLevel::Debug);
        assert_eq!(args.message.value(), "loaded block");
        assert!(!args.user);
    }

    #[test]
    fn rejects_string_level() {
        let err = parse_err(
            quote!(store::database, "loaded block", "debug", justification = "invalid level"),
            None,
        );

        assert!(err.to_string().contains("`level` must be one of"));
    }

    #[test]
    fn requires_target() {
        let err = parse_err(quote!(), Some(TelemetryLevel::Info));

        assert!(err.to_string().contains("`target` is required"));
    }

    #[test]
    fn rejects_user_value() {
        let err = parse_err(
            quote!(rpc, "accepted block", user = true, justification = "records a user milestone"),
            Some(TelemetryLevel::Info),
        );

        assert!(err.to_string().contains("`user` is a bare marker"));
    }

    #[test]
    fn rejects_level_argument_for_fixed_level_event() {
        let err = parse_err(
            quote!(rpc, "accepted block", info, justification = "invalid level"),
            Some(TelemetryLevel::Info),
        );

        assert!(err.to_string().contains("do not pass a level"));
    }

    #[test]
    fn rejects_extra_argument_for_explicit_level_event() {
        let err = parse_err(
            quote!(rpc, "accepted block", info, debug, justification = "extra argument"),
            None,
        );

        assert!(err.to_string().contains("only optional `user`"));
    }

    #[test]
    fn rejects_duplicate_user_after_target() {
        let err = parse_err(
            quote!(rpc, "accepted block", user, user, justification = "duplicate user"),
            Some(TelemetryLevel::Info),
        );

        assert!(err.to_string().contains("`user` may only be specified once"));
    }

    #[test]
    fn rejects_field_and_object_records() {
        let field_err = parse_err(quote!(rpc, field(block_num)), Some(TelemetryLevel::Info));
        let object_err = parse_err(quote!(rpc, object(block = header)), Some(TelemetryLevel::Info));

        assert!(
            field_err
                .to_string()
                .contains("`field(...)` and `object(...)` are not supported")
        );
        assert!(
            object_err
                .to_string()
                .contains("`field(...)` and `object(...)` are not supported")
        );
    }

    #[test]
    fn requires_justification_for_fixed_level_event() {
        let err = parse_err(quote!(rpc, "accepted block"), Some(TelemetryLevel::Info));

        assert!(err.to_string().contains("events are discouraged in favor of spans"));
    }

    #[test]
    fn requires_justification_after_user_marker() {
        let err = parse_err(quote!(rpc, "accepted block", user), Some(TelemetryLevel::Info));

        assert!(err.to_string().contains("events are discouraged in favor of spans"));
    }

    #[test]
    fn rejects_empty_justification() {
        let err = parse_err(
            quote!(rpc, "accepted block", justification = "   "),
            Some(TelemetryLevel::Info),
        );

        assert!(err.to_string().contains("`justification` must not be empty"));
    }

    #[test]
    fn rejects_non_literal_justification() {
        let err = parse_err(
            quote!(rpc, "accepted block", justification = REASON),
            Some(TelemetryLevel::Info),
        );

        assert!(err.to_string().contains("`justification` must be a non-empty string literal"));
    }

    #[test]
    fn requires_message_for_fixed_level_event() {
        let err = parse_err(quote!(rpc), Some(TelemetryLevel::Info));

        assert!(err.to_string().contains("`message` is required"));
    }

    #[test]
    fn requires_message_after_user() {
        let err = parse_err(quote!(sequencer::block_builder), Some(TelemetryLevel::Info));

        assert!(err.to_string().contains("`message` is required"));
    }

    #[test]
    fn requires_message_for_explicit_level_event() {
        let err = parse_err(quote!(store::database, "loaded block"), None);

        assert!(err.to_string().contains("`level` is required"));
    }

    #[test]
    fn requires_literal_message() {
        let err = parse_err(quote!(store::database, message, debug), None);

        assert!(err.to_string().contains("`message` must start with a string literal"));
    }

    #[test]
    fn rejects_format_arguments() {
        let err = parse_err(
            quote!(store::database, "loaded block {}", block_num, justification = "format args"),
            Some(TelemetryLevel::Info),
        );

        assert!(err.to_string().contains("only support optional `user`"));
    }
}
