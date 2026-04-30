use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream, Parser};
use syn::spanned::Spanned;
use syn::{Expr, Ident, LitStr, Token, parenthesized};

use crate::level::TelemetryLevel;
use crate::target;

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
    let event_name = quote! { ::std::format!(#message) };
    let records = args.records.iter().map(EventRecord::record_tokens);

    quote! {
        {
            // Use tracing's filter gate so disabled targets/levels do not pay to construct typed
            // event attributes, then record through our Span helper to keep the public macro
            // contract independent of the internal event representation.
            if ::miden_node_tracing::__private::tracing::event_enabled!(target: #target, #level) {
                let mut __miden_node_tracing_event =
                    ::miden_node_tracing::__private::OpenTelemetryEventRecorder::new();
                __miden_node_tracing_event.record_attribute("level", #level_name);
                __miden_node_tracing_event.record_attribute("target", #target);
                #(#records)*
                ::miden_node_tracing::Span::current()
                    .__record_event(#event_name, __miden_node_tracing_event);
            }
        }
    }
    .into()
}

struct EventArgs {
    target: String,
    target_span: proc_macro2::Span,
    level: TelemetryLevel,
    records: Vec<EventRecord>,
    message: proc_macro2::TokenStream,
}

impl EventArgs {
    fn parse(input: ParseStream<'_>, fixed_level: Option<TelemetryLevel>) -> syn::Result<Self> {
        if !input.peek(Ident) {
            return Err(syn::Error::new(
                input.span(),
                "`target` is required and must be the first argument",
            ));
        }
        let target_ident = input.parse::<Ident>()?;
        if target_ident != "target" {
            return Err(syn::Error::new_spanned(
                target_ident,
                "`target` is required and must be the first argument",
            ));
        }

        parse_key_separator(input, "`target`")?;
        let target_expr = input.parse::<Expr>()?;
        let target_span = target_expr.span();
        let target = target::parse(&target_expr)?;

        let level = if let Some(level) = fixed_level {
            level
        } else {
            input.parse::<Token![,]>()?;
            parse_level(input)?
        };

        if input.is_empty() {
            return Err(missing_message_error(input));
        }

        let mut records = Vec::new();

        input.parse::<Token![,]>()?;
        loop {
            if input.is_empty() {
                return Err(missing_message_error(input));
            }

            if let Some(record) = try_parse_record(input)? {
                records.push(record);
                if input.is_empty() {
                    return Err(missing_message_error(input));
                }
                input.parse::<Token![,]>()?;
            } else {
                let message = input.parse()?;
                return Ok(Self {
                    target,
                    target_span,
                    level,
                    records,
                    message,
                });
            }
        }
    }
}

fn missing_message_error(input: ParseStream<'_>) -> syn::Error {
    syn::Error::new(input.span(), "`message` is required and must follow any event records")
}

fn parse_level(input: ParseStream<'_>) -> syn::Result<TelemetryLevel> {
    let level_ident = input.parse::<Ident>()?;
    if level_ident != "level" {
        return Err(syn::Error::new_spanned(level_ident, "`level` is required after `target`"));
    }

    parse_key_separator(input, "`level`")?;
    let level = input.parse::<Expr>()?;
    TelemetryLevel::parse(&level)
}

fn try_parse_record(input: ParseStream<'_>) -> syn::Result<Option<EventRecord>> {
    let fork = input.fork();
    if !fork.peek(Ident) {
        return Ok(None);
    }

    let kind = fork.parse::<Ident>()?;
    let record_kind = match kind.to_string().as_str() {
        "field" => EventRecordKind::Field,
        "object" => EventRecordKind::Object,
        _ => return Ok(None),
    };
    if !fork.peek(syn::token::Paren) {
        return Ok(None);
    }

    input.parse::<Ident>()?;
    let content;
    parenthesized!(content in input);
    let record_arg = content.parse::<RecordArg>()?;
    if !content.is_empty() {
        return Err(syn::Error::new(content.span(), "unexpected tokens in event record"));
    }

    Ok(Some(EventRecord { kind: record_kind, arg: record_arg }))
}

fn parse_key_separator(input: ParseStream<'_>, name: &str) -> syn::Result<()> {
    if input.peek(Token![=]) {
        input.parse::<Token![=]>()?;
    } else if input.peek(Token![:]) {
        input.parse::<Token![:]>()?;
    } else {
        return Err(syn::Error::new(
            input.span(),
            format!("{name} must be followed by `=` or `:`"),
        ));
    }

    Ok(())
}

struct EventRecord {
    kind: EventRecordKind,
    arg: RecordArg,
}

impl EventRecord {
    fn record_tokens(&self) -> proc_macro2::TokenStream {
        let expr = &self.arg.expr;
        match (self.kind, &self.arg.key) {
            (EventRecordKind::Field, None) => {
                quote! { __miden_node_tracing_event.record_field(&#expr); }
            },
            (EventRecordKind::Field, Some(key)) => {
                quote! { __miden_node_tracing_event.record_field_as(&#expr, #key); }
            },
            (EventRecordKind::Object, None) => {
                quote! { __miden_node_tracing_event.record_object(&#expr); }
            },
            (EventRecordKind::Object, Some(key)) => {
                quote! { __miden_node_tracing_event.record_object_as(&#expr, #key); }
            },
        }
    }
}

#[derive(Clone, Copy)]
enum EventRecordKind {
    Field,
    Object,
}

struct RecordArg {
    key: Option<LitStr>,
    expr: Expr,
}

impl Parse for RecordArg {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let fork = input.fork();
        if fork.parse::<RecordKey>().is_ok() {
            if fork.peek(Token![=]) {
                let key = input.parse::<RecordKey>()?;
                input.parse::<Token![=]>()?;
                let expr = input.parse()?;
                return Ok(Self { key: Some(key.into_lit_str()), expr });
            }
        }

        Ok(Self { key: None, expr: input.parse()? })
    }
}

enum RecordKey {
    Path { value: String, span: proc_macro2::Span },
    Literal(LitStr),
}

impl RecordKey {
    fn into_lit_str(self) -> LitStr {
        match self {
            Self::Path { value, span } => LitStr::new(&value, span),
            Self::Literal(lit) => lit,
        }
    }
}

impl Parse for RecordKey {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        if input.peek(LitStr) {
            return Ok(Self::Literal(input.parse()?));
        }

        let first = input.parse::<Ident>()?;
        let span = first.span();
        let mut value = first.to_string();

        while input.peek(Token![.]) {
            input.parse::<Token![.]>()?;
            let segment = input.parse::<Ident>()?;
            value.push('.');
            value.push_str(&segment.to_string());
        }

        Ok(Self::Path { value, span })
    }
}

#[cfg(test)]
mod tests {
    use quote::quote;
    use syn::parse::Parser;

    use super::{EventArgs, EventRecordKind};
    use crate::level::TelemetryLevel;

    fn parse_args(
        tokens: proc_macro2::TokenStream,
        fixed_level: Option<TelemetryLevel>,
    ) -> syn::Result<EventArgs> {
        (|input: syn::parse::ParseStream<'_>| EventArgs::parse(input, fixed_level)).parse2(tokens)
    }

    #[test]
    fn parses_level_event_args() {
        let args = parse_args(
            quote!(
                target = rpc,
                field(block_num),
                object(block = header),
                "accepted block {}",
                block_num
            ),
            Some(TelemetryLevel::Info),
        )
        .unwrap();

        assert_eq!(args.target, "rpc");
        assert_eq!(args.level, TelemetryLevel::Info);
        assert_eq!(args.records.len(), 2);
        assert!(matches!(args.records[0].kind, EventRecordKind::Field));
        assert!(matches!(args.records[1].kind, EventRecordKind::Object));
        assert!(args.message.to_string().contains("accepted block"));
    }

    #[test]
    fn parses_event_macro_level() {
        let args =
            parse_args(quote!(target = store::database, level = debug, "loaded block"), None)
                .unwrap();

        assert_eq!(args.target, "store::database");
        assert_eq!(args.level, TelemetryLevel::Debug);
        assert!(args.message.to_string().contains("loaded block"));
    }

    #[test]
    fn rejects_string_level() {
        let err = match parse_args(quote!(target = store::database, level = "debug"), None) {
            Ok(_) => panic!("event args should fail to parse"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("`level` must be one of"));
    }

    #[test]
    fn requires_target() {
        let err = match parse_args(quote!("message"), Some(TelemetryLevel::Info)) {
            Ok(_) => panic!("event args should fail to parse"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("`target` is required"));
    }

    #[test]
    fn requires_message_for_fixed_level_event() {
        let err = match parse_args(quote!(target = rpc), Some(TelemetryLevel::Info)) {
            Ok(_) => panic!("event args should fail to parse"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("`message` is required"));
    }

    #[test]
    fn requires_message_after_records() {
        let err = match parse_args(
            quote!(target = sequencer::block_builder, field(block_num)),
            Some(TelemetryLevel::Info),
        ) {
            Ok(_) => panic!("event args should fail to parse"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("`message` is required"));
    }

    #[test]
    fn requires_message_for_explicit_level_event() {
        let err = match parse_args(quote!(target = store::database, level = debug), None) {
            Ok(_) => panic!("event args should fail to parse"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("`message` is required"));
    }
}
