use std::collections::BTreeSet;

use proc_macro::TokenStream;
use proc_macro2::{Delimiter, Group, TokenStream as TokenStream2, TokenTree};
use quote::{ToTokens, quote};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::token::Dot;
use syn::visit::Visit;
use syn::{
    Attribute,
    Block,
    Expr,
    Ident,
    ItemFn,
    LitStr,
    Macro,
    Meta,
    Result,
    Token,
    parse_macro_input,
    parse_quote,
};

mod instrument;

/// Instruments a function using canonical tracing attributes.
///
/// Field values must implement `RecordAttribute`, and their names must be registered for the value
/// type. A field whose name ends in `.count` accepts any `usize` without registration. Append
/// `#[nonstandard]` to any other field value to permit an unregistered name while retaining its
/// canonical encoding.
///
/// `err` records a typed error. The subscriber controls how it records the source chain.
/// Errors must implement `std::error::Error + 'static` or dereference to that trait.
/// `err(level = "warn")` sets the event level. Error formatters are not supported.
#[proc_macro_attribute]
pub fn miden_instrument(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr = match rewrite_explicit_fields(TokenStream2::from(attr)) {
        Ok(attr) => attr,
        Err(error) => return error.into_compile_error().into(),
    };
    let mut function = parse_macro_input!(item as ItemFn);
    let fields = collect_recorded_fields(&function);
    let attr = match instrument::instrument_result(attr, &mut function) {
        Ok(attr) => attr,
        Err(error) => return error.into_compile_error().into(),
    };
    let args = match merge_inferred_fields(attr, &fields) {
        Ok(args) => args,
        Err(error) => return error.into_compile_error().into(),
    };
    let statements = &function.block.stmts;
    let block: Block = parse_quote! {{
        #[allow(unused_macros)]
        macro_rules! __miden_span_record_must_be_used_within_miden_instrument {
            () => {};
        }

        #(#statements)*
    }};
    *function.block = block;

    let expanded = quote! {
        #[::miden_node_tracing::__private::instrument(#args)]
        #function
    };

    expanded.into()
}

/// Emits a trace-level event.
///
/// An optional first argument can provide a typed error. The error must implement
/// `std::error::Error + 'static` or dereference to that trait. The OpenTelemetry layer records
/// its message as `exception.message` and its sources as `exception.stacktrace`.
///
/// The event name is required and must be a string literal. When an error is provided, optional
/// `target:` and `parent:` arguments go between the error and name, in that order. Without an
/// error, they precede the name. Attributes follow the name and must use a registered field name
/// and a value implementing `RecordAttribute`. Append `#[nonstandard]` to a field value to permit
/// an unregistered name while retaining its canonical encoding. Tracing format specifiers and
/// trailing commas are not supported.
///
/// The name is recorded as tracing's `message` field, which the OpenTelemetry tracing layer uses
/// as the event name.
///
/// ```rust,ignore
/// use miden_node_tracing::trace;
///
/// trace!(target: "node", "block.received", block.number = 42_u32);
///
/// let source = std::io::Error::other("invalid block");
/// trace!(&source, "block.rejected", block.number = 42_u32);
/// ```
#[proc_macro]
pub fn trace(input: TokenStream) -> TokenStream {
    expand_event(input, "trace", false)
}

/// Emits a debug-level event.
///
/// An optional first argument can provide a typed error. The error must implement
/// `std::error::Error + 'static` or dereference to that trait. The OpenTelemetry layer records
/// its message as `exception.message` and its sources as `exception.stacktrace`.
///
/// The event name is required and must be a string literal. When an error is provided, optional
/// `target:` and `parent:` arguments go between the error and name, in that order. Without an
/// error, they precede the name. Attributes follow the name and must use a registered field name
/// and a value implementing `RecordAttribute`. Append `#[nonstandard]` to a field value to permit
/// an unregistered name while retaining its canonical encoding. Tracing format specifiers and
/// trailing commas are not supported.
///
/// The name is recorded as tracing's `message` field, which the OpenTelemetry tracing layer uses
/// as the event name.
///
/// ```rust,ignore
/// use miden_node_tracing::debug;
///
/// debug!("block.queued", block.number = 42_u32);
///
/// let source = std::io::Error::other("upstream unavailable");
/// debug!(&source, "block.retrying", block.number = 42_u32);
/// ```
#[proc_macro]
pub fn debug(input: TokenStream) -> TokenStream {
    expand_event(input, "debug", false)
}

/// Emits an info-level event.
///
/// An optional first argument can provide a typed error. The error must implement
/// `std::error::Error + 'static` or dereference to that trait. The OpenTelemetry layer records
/// its message as `exception.message` and its sources as `exception.stacktrace`.
///
/// The event name is required and must be a string literal. When an error is provided, optional
/// `target:` and `parent:` arguments go between the error and name, in that order. Without an
/// error, they precede the name. Attributes follow the name and must use a registered field name
/// and a value implementing `RecordAttribute`. Append `#[nonstandard]` to a field value to permit
/// an unregistered name while retaining its canonical encoding. Tracing format specifiers and
/// trailing commas are not supported.
///
/// The name is recorded as tracing's `message` field, which the OpenTelemetry tracing layer uses
/// as the event name.
///
/// ```rust,ignore
/// use miden_node_tracing::info;
///
/// let parent = tracing::info_span!("block");
/// info!(parent: &parent, "block.accepted", block.number = 42_u32);
///
/// let source = std::io::Error::other("used fallback");
/// info!(&source, "block.fallback_used", block.number = 42_u32);
/// ```
#[proc_macro]
pub fn info(input: TokenStream) -> TokenStream {
    expand_event(input, "info", false)
}

/// Emits a warning-level event.
///
/// An optional first argument can provide a typed error. The error must implement
/// `std::error::Error + 'static` or dereference to that trait. The OpenTelemetry layer records
/// its message as `exception.message` and its sources as `exception.stacktrace`.
///
/// The event name is required and must be a string literal. When an error is provided, optional
/// `target:` and `parent:` arguments go between the error and name, in that order. Without an
/// error, they precede the name. Attributes follow the name and must use a registered field name
/// and a value implementing `RecordAttribute`. Append `#[nonstandard]` to a field value to permit
/// an unregistered name while retaining its canonical encoding. Tracing format specifiers and
/// trailing commas are not supported.
///
/// The name is recorded as tracing's `message` field, which the OpenTelemetry tracing layer uses
/// as the event name.
///
/// ```rust,ignore
/// use miden_node_tracing::warn;
///
/// warn!("block.delayed", block.number = 42_u32);
///
/// let source = std::io::Error::other("upstream unavailable");
/// warn!(&source, "block.retrying", block.number = 42_u32);
/// ```
#[proc_macro]
pub fn warn(input: TokenStream) -> TokenStream {
    expand_event(input, "warn", false)
}

/// Emits an error-level event with a typed error.
///
/// The first argument is required. It must implement `std::error::Error + 'static` or dereference
/// to that trait. The OpenTelemetry layer records its message as `exception.message` and its
/// sources as `exception.stacktrace`.
///
/// The event name follows the error and must be a string literal. Optional `target:` and `parent:`
/// arguments go between the error and name, in that order. Additional attributes follow the name
/// and must use a registered field name and a value implementing `RecordAttribute`. Append
/// `#[nonstandard]` to a field value to permit an unregistered name while retaining its canonical
/// encoding. Tracing format specifiers and trailing commas are not supported.
///
/// The name is recorded as tracing's `message` field, which the OpenTelemetry tracing layer uses
/// as the event name.
///
/// ```rust,ignore
/// use miden_node_tracing::error;
///
/// let source = std::io::Error::other("database unavailable");
/// error!(source, target: "node", "block.store_failed", block.number = 42_u32);
/// ```
#[proc_macro]
pub fn error(input: TokenStream) -> TokenStream {
    expand_event(input, "error", true)
}

fn expand_event(input: TokenStream, level: &str, error_required: bool) -> TokenStream {
    let event = if error_required {
        syn::parse::<ErrorEvent>(input).map(|event| event.0)
    } else {
        syn::parse::<OptionalErrorEvent>(input).map(|event| event.0)
    };
    let event = match event {
        Ok(event) => event,
        Err(error) => return error.into_compile_error().into(),
    };

    event.tokens(&Ident::new(level, proc_macro2::Span::call_site())).into()
}

struct ErrorEvent(Event);

impl Parse for ErrorEvent {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let event = parse_error_event(input)?;
        event.reject_exception_fields()?;

        Ok(Self(event))
    }
}

struct OptionalErrorEvent(Event);

impl Parse for OptionalErrorEvent {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let event = if starts_without_error(input) {
            Event::parse_after_error(input, None)?
        } else {
            parse_error_event(input)?
        };
        event.reject_exception_fields()?;

        Ok(Self(event))
    }
}

fn parse_error_event(input: ParseStream<'_>) -> Result<Event> {
    if input.is_empty() {
        return Err(input.error("expected an error expression"));
    }

    let error = input.parse()?;
    if input.is_empty() {
        return Err(syn::Error::new_spanned(error, "expected a static event name string literal"));
    }
    input.parse::<Token![,]>()?;

    Event::parse_after_error(input, Some(error))
}

struct Event {
    error: Option<Expr>,
    target: Option<Expr>,
    parent: Option<Expr>,
    name: LitStr,
    fields: Vec<RecordField>,
}

impl Event {
    fn parse_after_error(input: ParseStream<'_>, error: Option<Expr>) -> Result<Self> {
        let target = if input.peek(event_kw::target) {
            input.parse::<event_kw::target>()?;
            input.parse::<Token![:]>()?;
            let target = input.parse()?;
            input.parse::<Token![,]>()?;
            Some(target)
        } else {
            None
        };

        let parent = if input.peek(event_kw::parent) {
            input.parse::<event_kw::parent>()?;
            input.parse::<Token![:]>()?;
            let parent = input.parse()?;
            input.parse::<Token![,]>()?;
            Some(parent)
        } else {
            None
        };

        let name = input
            .parse::<LitStr>()
            .map_err(|_| input.error("expected a static event name string literal"))?;
        let mut fields = Vec::new();

        if !input.is_empty() {
            let comma = input.parse::<Token![,]>()?;
            if input.is_empty() {
                return Err(syn::Error::new_spanned(comma, "trailing commas are not supported"));
            }

            loop {
                fields.push(RecordField::parse(input, true)?);
                if input.is_empty() {
                    break;
                }

                let comma = input.parse::<Token![,]>()?;
                if input.is_empty() {
                    return Err(syn::Error::new_spanned(
                        comma,
                        "trailing commas are not supported",
                    ));
                }
            }
        }

        Ok(Self { error, target, parent, name, fields })
    }

    fn reject_exception_fields(&self) -> Result<()> {
        if let Some(field) = self.fields.iter().find(|field| {
            matches!(field.path.name().as_str(), "exception.message" | "exception.stacktrace")
        }) {
            Err(syn::Error::new_spanned(
                &field.path,
                format!(
                    "pass the error as the first argument instead of recording `{}`",
                    field.path.name()
                ),
            ))
        } else {
            Ok(())
        }
    }

    fn tokens(&self, level: &Ident) -> TokenStream2 {
        let target = self.target.as_ref().map(|target| quote! { target: #target, });
        let parent = self.parent.as_ref().map(|parent| quote! { parent: #parent, });
        let name = &self.name;
        let error_import = self.error.as_ref().map(|_| {
            quote! { use ::miden_node_tracing::__private::AsDynError as _; }
        });
        let error = self.error.as_ref().map(|error| {
            quote! {
                , error = (#error).as_dyn_error()
            }
        });
        let fields = self.fields.iter().map(RecordField::instrument_tokens);

        quote! {{
            #error_import
            ::miden_node_tracing::__private::#level!(
                #target
                #parent
                message = #name
                #error
                #(, #fields)*
            )
        }}
    }
}

mod event_kw {
    syn::custom_keyword!(parent);
    syn::custom_keyword!(target);
}

fn starts_without_error(input: ParseStream<'_>) -> bool {
    if input.peek(LitStr) {
        return true;
    }

    let ahead = input.fork();
    let starts_with_target =
        ahead.parse::<event_kw::target>().is_ok() && ahead.parse::<Token![:]>().is_ok();
    if starts_with_target {
        return true;
    }

    let ahead = input.fork();
    ahead.parse::<event_kw::parent>().is_ok() && ahead.parse::<Token![:]>().is_ok()
}

fn merge_inferred_fields(attr: TokenStream2, fields: &[FieldPath]) -> Result<TokenStream2> {
    let mut args = split_top_level_args(attr);
    reject_skip_directives(&args)?;

    // Function arguments often contain large or sensitive values. Always skip them so spans only
    // contain fields explicitly declared by the caller or inferred from `miden_span_record!`.
    args.push(quote! { skip_all });

    if fields.is_empty() {
        return Ok(quote! { #(#args),* });
    }

    let inferred_fields = quote! { #(#fields = ::miden_node_tracing::field::Empty),* };
    let mut merged_existing_fields = false;
    let args = args
        .into_iter()
        .map(|arg| {
            if let Some(group) = fields_group(&arg) {
                merged_existing_fields = true;
                let existing_fields = group.stream();
                let merged_fields = if existing_fields.is_empty() {
                    inferred_fields.clone()
                } else if ends_with_comma(&existing_fields) {
                    quote! { #existing_fields #inferred_fields }
                } else {
                    quote! { #existing_fields, #inferred_fields }
                };
                let mut merged_group = Group::new(Delimiter::Parenthesis, merged_fields);
                merged_group.set_span(group.span());
                quote! { fields #merged_group }
            } else {
                arg
            }
        })
        .collect::<Vec<_>>();

    if merged_existing_fields {
        Ok(quote! { #(#args),* })
    } else {
        Ok(quote! { #(#args,)* fields(#inferred_fields) })
    }
}

fn reject_skip_directives(args: &[TokenStream2]) -> Result<()> {
    for arg in args {
        let Some(TokenTree::Ident(ident)) = arg.clone().into_iter().next() else {
            continue;
        };
        if ident == "skip" || ident == "skip_all" {
            return Err(syn::Error::new_spanned(
                arg,
                format!(
                    "`{ident}` is not supported by `miden_instrument`; function arguments are \
                     always skipped, record fields explicitly with `fields(...)`"
                ),
            ));
        }
    }

    Ok(())
}

fn rewrite_explicit_fields(attr: TokenStream2) -> Result<TokenStream2> {
    let args = split_top_level_args(attr)
        .into_iter()
        .map(|arg| {
            if let Some(group) = fields_group(&arg) {
                let fields = syn::parse2::<InstrumentFields>(group.stream())?;
                let fields = fields.fields.iter().map(RecordField::instrument_tokens);
                let mut rewritten = Group::new(Delimiter::Parenthesis, quote! { #(#fields),* });
                rewritten.set_span(group.span());
                Ok(quote! { fields #rewritten })
            } else {
                Ok(arg)
            }
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(quote! { #(#args),* })
}

fn reject_formatter(input: ParseStream<'_>) -> Result<()> {
    let formatter = if input.peek(Token![%]) {
        Some(input.parse::<Token![%]>()?.span)
    } else if input.peek(Token![?]) {
        Some(input.parse::<Token![?]>()?.span)
    } else {
        None
    };

    if let Some(span) = formatter {
        Err(syn::Error::new(
            span,
            "tracing format specifiers are not supported; implement `RecordAttribute` to define \
             the type's canonical encoding",
        ))
    } else {
        Ok(())
    }
}

impl RecordField {
    fn instrument_tokens(&self) -> TokenStream2 {
        let path = &self.path;
        if let Some(value) = &self.value {
            let value = value.value_tokens(&self.path.name(), self.path.is_count());
            quote! { #path = #value }
        } else {
            quote! { #path }
        }
    }
}

fn split_top_level_args(tokens: TokenStream2) -> Vec<TokenStream2> {
    let mut args = Vec::new();
    let mut current = TokenStream2::new();

    for token in tokens {
        match &token {
            TokenTree::Punct(punct) if punct.as_char() == ',' => {
                args.push(current);
                current = TokenStream2::new();
            },
            _ => current.extend([token]),
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    args
}

fn fields_group(arg: &TokenStream2) -> Option<Group> {
    let mut tokens = arg.clone().into_iter();
    let Some(TokenTree::Ident(ident)) = tokens.next() else {
        return None;
    };
    if ident != "fields" {
        return None;
    }

    let Some(TokenTree::Group(group)) = tokens.next() else {
        return None;
    };
    if group.delimiter() != Delimiter::Parenthesis || tokens.next().is_some() {
        return None;
    }

    Some(group)
}

fn ends_with_comma(tokens: &TokenStream2) -> bool {
    matches!(
        tokens.clone().into_iter().last(),
        Some(TokenTree::Punct(punct)) if punct.as_char() == ','
    )
}

/// Records canonical attributes on the current `miden_instrument` span.
///
/// Field values must implement `RecordAttribute`, and their names must be registered for the value
/// type. A field whose name ends in `.count` accepts any `usize` without registration. Append
/// `#[nonstandard]` to any other field value to permit an unregistered name while retaining its
/// canonical encoding.
#[proc_macro]
pub fn miden_span_record(input: TokenStream) -> TokenStream {
    let records = parse_macro_input!(input as RecordFields);
    let records = records.fields.into_iter().map(|field| {
        let name = field.path.name();
        let value = field
            .value
            .expect("record fields are parsed with required values")
            .value_tokens(&name, field.path.is_count());

        quote! {
            ::miden_node_tracing::Span::current().record(#name, #value);
        }
    });

    quote! {
        __miden_span_record_must_be_used_within_miden_instrument!();
        #(#records)*
    }
    .into()
}

fn collect_recorded_fields(function: &ItemFn) -> Vec<FieldPath> {
    let mut visitor = MacroVisitor::default();
    visitor.visit_block(&function.block);

    let mut names = BTreeSet::new();
    visitor.fields.into_iter().filter(|field| names.insert(field.name())).collect()
}

#[derive(Default)]
struct MacroVisitor {
    fields: Vec<FieldPath>,
}

impl<'ast> Visit<'ast> for MacroVisitor {
    fn visit_macro(&mut self, mac: &'ast Macro) {
        if mac
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "miden_span_record")
        {
            if let Ok(records) = syn::parse2::<RecordFields>(mac.tokens.clone()) {
                self.fields.extend(records.fields.into_iter().map(|field| field.path));
            }
        }

        syn::visit::visit_macro(self, mac);
    }
}

type InstrumentFields = Fields<false>;
type RecordFields = Fields<true>;

struct Fields<const VALUE_REQUIRED: bool> {
    fields: Punctuated<RecordField, Token![,]>,
}

impl<const VALUE_REQUIRED: bool> Parse for Fields<VALUE_REQUIRED> {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        Ok(Self {
            fields: Punctuated::parse_terminated_with(input, |input| {
                RecordField::parse(input, VALUE_REQUIRED)
            })?,
        })
    }
}

struct RecordField {
    path: FieldPath,
    value: Option<RecordValue>,
}

impl RecordField {
    fn parse(input: ParseStream<'_>, value_required: bool) -> Result<Self> {
        reject_formatter(input)?;
        let path = input.parse()?;
        let value = if value_required || input.peek(Token![=]) {
            input.parse::<Token![=]>()?;
            reject_formatter(input)?;
            Some(input.parse()?)
        } else {
            None
        };

        Ok(Self { path, value })
    }
}

struct FieldPath {
    first: Ident,
    rest: Vec<(Dot, Ident)>,
}

impl FieldPath {
    fn name(&self) -> String {
        std::iter::once(&self.first)
            .chain(self.rest.iter().map(|(_, ident)| ident))
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(".")
    }

    fn is_count(&self) -> bool {
        self.rest.last().is_some_and(|(_, ident)| ident == "count")
    }
}

impl Parse for FieldPath {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let first = input.parse()?;
        let mut rest = Vec::new();

        while input.peek(Token![.]) {
            rest.push((input.parse()?, input.parse()?));
        }

        Ok(Self { first, rest })
    }
}

impl ToTokens for FieldPath {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        self.first.to_tokens(tokens);
        for (dot, ident) in &self.rest {
            dot.to_tokens(tokens);
            ident.to_tokens(tokens);
        }
    }
}

struct RecordValue {
    expr: Expr,
    nonstandard: bool,
}

impl RecordValue {
    fn value_tokens(&self, field_name: &str, is_count: bool) -> TokenStream2 {
        let expr = &self.expr;
        let assert_field_name = (!self.nonstandard && !is_count).then(|| {
            quote! {
                fn __miden_assert_field_name<T>(_: &T)
                where
                    T: ::miden_node_tracing::RecordAttribute + ?Sized,
                {
                    const {
                        assert!(
                            ::miden_node_tracing::field_name_allowed(
                                T::FIELD_NAMES,
                                #field_name,
                                T::PLURALIZE_FIELD_NAMES,
                            ),
                            concat!(
                                "tracing field `",
                                #field_name,
                                "` is not allowed for this attribute type",
                            ),
                        );
                    }
                }

                __miden_assert_field_name(value);
            }
        });
        let assert_count = is_count.then(|| {
            quote! {
                fn __miden_assert_count(_: &usize) {}

                __miden_assert_count(value);
            }
        });

        quote! {
            match &(#expr) {
                value => {
                    #assert_field_name
                    #assert_count
                    ::miden_node_tracing::record_attribute(value)
                }
            }
        }
    }
}

impl Parse for RecordValue {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let expr = input.parse()?;
        let attributes = input.call(Attribute::parse_outer)?;
        let nonstandard = match attributes.as_slice() {
            [] => false,
            [attribute] if matches!(&attribute.meta, Meta::Path(path) if path.is_ident("nonstandard")) => {
                true
            },
            [attribute, ..] => {
                return Err(syn::Error::new_spanned(
                    attribute,
                    "only `#[nonstandard]` is supported after a tracing field value",
                ));
            },
        };

        Ok(Self { expr, nonstandard })
    }
}
