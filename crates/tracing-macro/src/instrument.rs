use std::str::FromStr;

use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{Expr, Ident, ItemFn, LitStr, PathSegment, ReturnType, Token, Type, TypeImplTrait};

mod kw {
    syn::custom_keyword!(ret);
    syn::custom_keyword!(root);
    syn::custom_keyword!(err);
    syn::custom_keyword!(report);
    syn::custom_keyword!(level);
    syn::custom_keyword!(INFO);
    syn::custom_keyword!(DEBUG);
    syn::custom_keyword!(TRACE);
    syn::custom_keyword!(WARN);
    syn::custom_keyword!(ERROR);
}

/// The span level declared with `level: LEVEL`.
#[derive(Clone)]
enum SpanLevel {
    Info,
    Debug,
    Trace,
    Warn,
    Error,
}

impl SpanLevel {
    /// Emits the `::tracing::Level::*` token for use in `span!()`.
    fn to_level_tokens(&self) -> TokenStream2 {
        match self {
            SpanLevel::Info => quote! { ::tracing::Level::INFO },
            SpanLevel::Debug => quote! { ::tracing::Level::DEBUG },
            SpanLevel::Trace => quote! { ::tracing::Level::TRACE },
            SpanLevel::Warn => quote! { ::tracing::Level::WARN },
            SpanLevel::Error => quote! { ::tracing::Level::ERROR },
        }
    }

    /// Lowercase string for `#[tracing::instrument(level = "…")]`.
    fn as_str(&self) -> &'static str {
        match self {
            SpanLevel::Info => "info",
            SpanLevel::Debug => "debug",
            SpanLevel::Trace => "trace",
            SpanLevel::Warn => "warn",
            SpanLevel::Error => "error",
        }
    }
}

impl Parse for SpanLevel {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(kw::INFO) {
            input.parse::<kw::INFO>()?;
            Ok(SpanLevel::Info)
        } else if lookahead.peek(kw::DEBUG) {
            input.parse::<kw::DEBUG>()?;
            Ok(SpanLevel::Debug)
        } else if lookahead.peek(kw::TRACE) {
            input.parse::<kw::TRACE>()?;
            Ok(SpanLevel::Trace)
        } else if lookahead.peek(kw::WARN) {
            input.parse::<kw::WARN>()?;
            Ok(SpanLevel::Warn)
        } else if lookahead.peek(kw::ERROR) {
            input.parse::<kw::ERROR>()?;
            Ok(SpanLevel::Error)
        } else {
            Err(lookahead.error())
        }
    }
}

// ── Name ──────────────────────────────────────────────────────────────────────

/// An open telemetry like dotted identifier (e.g. `account.id`, `block.number`), parsed from
/// the attribute stream but **not yet** checked against the allowlist.
///
/// Grammar: `ident ("." ident)*`
pub(crate) struct Name {
    pub(crate) segments: Punctuated<Ident, Token![.]>,
}

impl Name {
    /// Returns the dotted string representation, e.g. `"account.id"`.
    pub(crate) fn to_dotted_string(&self) -> String {
        self.segments.iter().map(ToString::to_string).collect::<Vec<_>>().join(".")
    }

    /// Span for the full name.
    pub(crate) fn span(&self) -> Span {
        self.segments.span()
    }

    /// Validates this name against the OpenTelemetry allowlist and, on success, returns a
    /// [`CheckedName`] that carries the pre-computed dotted string and span.
    ///
    /// On failure, emits a [`syn::Error`] anchored at the name's span. If the
    /// fuzzy-search backend finds close matches they are included as suggestions.
    pub(crate) fn check(self) -> syn::Result<CheckedName> {
        let dotted = self.to_dotted_string();
        let span = self.span();
        crate::allowed::check(&dotted).map_err(|suggestions| {
            let hint = if suggestions.is_empty() {
                String::new()
            } else {
                format!(" – did you mean: {}?", suggestions.join(", "))
            };
            syn::Error::new(span, format!("`{dotted}` is not in the OpenTelemetry allowlist{hint}"))
        })?;
        Ok(CheckedName { dotted, span })
    }
}

impl Parse for Name {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut segments = Punctuated::new();
        segments.push_value(input.parse::<Ident>()?);
        while input.peek(Token![.]) {
            segments.push_punct(input.parse::<Token![.]>()?);
            segments.push_value(input.parse::<Ident>()?);
        }
        Ok(Name { segments })
    }
}

// ── CheckedName ───────────────────────────────────────────────────────────────

/// A field name that has been validated against the OpenTelemetry allowlist.
///
/// The only way to construct a `CheckedName` is via [`Name::check`], ensuring
/// that unchecked names can never reach codegen.
pub(crate) struct CheckedName {
    /// Pre-computed dotted representation (e.g. `"account.id"`).
    pub(crate) dotted: String,
    /// Span of the original [`Name`] token, forwarded for error reporting.
    pub(crate) span: Span,
}

// ── Value ─────────────────────────────────────────────────────────────────────

/// The right-hand side of a field assignment: an optional format modifier
/// followed by an arbitrary expression.
///
/// - `= expr`  → Debug format (`{:?}`)
/// - `= %expr` → Display format (`{}`)
/// - `= ?expr` → Debug format (`{:?}`), explicit
struct Value {
    display_modifier: Option<Token![%]>,
    expr: Expr,
}

impl Parse for Value {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // Consume `%` (Display) or `?` (Debug-explicit). Both are accepted for
        // consistency with `tracing`'s own field syntax; only `%` affects the
        // generated token (Debug is the default and needs no modifier token).
        let display_modifier = if input.peek(Token![%]) {
            Some(input.parse::<Token![%]>()?)
        } else {
            // Consume and discard `?` so the following expr parses cleanly.
            input.parse::<Token![?]>().ok();
            None
        };
        let expr = input.parse::<Expr>()?;
        Ok(Value { display_modifier, expr })
    }
}

// ── Field entry ───────────────────────────────────────────────────────────────

/// A single `dotted-name = [%] expr` pair inside the attribute list.
///
/// The `name` has been validated against the OpenTelemetry allowlist at parse time.
/// Both `account.id = id` (Debug) and `account.id = %id` (Display) are accepted.
struct Field {
    name: CheckedName,
    value: Value,
}

impl Parse for Field {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let raw: Name = input.parse()?;
        let name = raw.check()?;
        let _eq: Token![=] = input.parse()?;
        let value: Value = input.parse()?;
        Ok(Field { name, value })
    }
}

// ── Element ───────────────────────────────────────────────────────────────────

/// A single comma-separated element inside the `#[instrument(…)]` attribute.
enum Element {
    /// A `dotted-name = [%] expr` field (validated against the OpenTelemetry allowlist).
    Field(Box<Field>),
    /// `ret` – record the function's return value inside the span.
    Ret,
    /// `root` – force the span to be a root span (`parent = None`).
    Root,
    /// `err` – on `Err`, emit a tracing event with the top-level error message.
    /// Delegates to `tracing::instrument`'s built-in `err`.  Requires `Result`.
    Err,
    /// `report` – on `Err`, walk the full error chain via [`ErrorReport`] and set
    /// the OpenTelemetry span status.  Mutually exclusive with `err`.  Requires `Result`.
    Report,
    /// `level: INFO | DEBUG | TRACE | WARN | ERROR` – override the span level (default: `INFO`).
    Level(SpanLevel),
}

impl Parse for Element {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(kw::ret) {
            input.parse::<kw::ret>()?;
            Ok(Element::Ret)
        } else if input.peek(kw::root) {
            input.parse::<kw::root>()?;
            Ok(Element::Root)
        } else if input.peek(kw::err) {
            input.parse::<kw::err>()?;
            Ok(Element::Err)
        } else if input.peek(kw::report) {
            input.parse::<kw::report>()?;
            Ok(Element::Report)
        } else if input.peek(kw::level) {
            input.parse::<kw::level>()?;
            let _: Token![:] = input.parse()?;
            Ok(Element::Level(input.parse()?))
        } else {
            Ok(Element::Field(Box::new(input.parse()?)))
        }
    }
}

// ── ComponentName ─────────────────────────────────────────────────────────────

/// The optional component prefix before the `:` separator.
///
/// Used by both `#[instrument(…)]` and the log macros (`warn!`, `error!`, …),
/// but with different token syntax in the emitted output:
/// - span attributes use `=`  (e.g. `target = "rpc"`)
/// - tracing events use `:`  (e.g. `target: "rpc"`)
///
/// ```text
/// #[instrument(rpc: …)]          → Ident("rpc")   → target = "rpc"
/// #[instrument("my-rpc": …)]     → Literal → target = "my-rpc"
/// ```
pub(crate) enum ComponentName {
    Literal(LitStr),
    Ident(Ident),
}

impl ComponentName {
    fn as_string(&self) -> String {
        match self {
            ComponentName::Literal(lit) => lit.value(),
            ComponentName::Ident(ident) => ident.to_string(),
        }
    }

    /// Emits `target: "…",` for use in `tracing::<level>!(…)` event macros.
    pub(crate) fn to_event_target_tokens(&self) -> TokenStream2 {
        match self {
            ComponentName::Literal(lit) => quote! { target: #lit, },
            ComponentName::Ident(ident) => {
                let s = ident.to_string();
                let lit = LitStr::new(&s, ident.span());
                quote! { target: #lit, }
            },
        }
    }
}

// ── InstrumentArgs ────────────────────────────────────────────────────────────

/// Parsed representation of the full `#[instrument(…)]` attribute.
///
/// Grammar:
/// ```text
/// InstrumentArgs ::= ε
///                  | COMPONENT ":" [element ("," element)*]
///                  | COMPONENT
///                  | element ("," element)*
///
/// COMPONENT  ::= ident | string-literal
/// element    ::= field-entry | "ret" | "root" | "err" | "report" | "level" ":" LEVEL
/// LEVEL       ::= "INFO" | "DEBUG" | "TRACE" | "WARN" | "ERROR"
/// field-entry ::= dotted-name "=" ["%"] expr
/// ```
struct InstrumentArgs {
    /// The `COMPONENT:` prefix, if present.  Maps to `target = "…"` in the
    /// underlying `tracing::instrument`.
    component: Option<ComponentName>,
    /// Comma-separated elements following the optional component prefix.
    elements: Vec<Element>,
}

impl Parse for InstrumentArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.is_empty() {
            return Ok(InstrumentArgs { component: None, elements: Vec::new() });
        }

        // Detect `COMPONENT:` prefix: an ident (or string literal) followed by `:`.
        // The colon disambiguates from `field = value` entries whose names also
        // start with an ident.
        //
        // A bare `COMPONENT` without a colon is also accepted when it is the only
        // token in the attribute (e.g. `#[instrument(COMPONENT)]`), since no
        // element can start with a lone ident that has no `=` or `.` after it.
        let component = if input.peek(LitStr) && input.peek2(Token![:]) {
            let lit: LitStr = input.parse()?;
            let _colon: Token![:] = input.parse()?;
            Some(ComponentName::Literal(lit))
        } else if input.peek(Ident) && input.peek2(Token![:]) {
            let ident: Ident = input.parse()?;
            let _colon: Token![:] = input.parse()?;
            Some(ComponentName::Ident(ident))
        } else if input.peek(Ident) {
            // Bare `COMPONENT` without colon: accepted only when the ident is the
            // sole token (nothing follows it) and it is not a reserved keyword.
            let forked = input.fork();
            let ident: Ident = forked.parse().expect("peek verified Ident");
            let is_keyword =
                matches!(ident.to_string().as_str(), "ret" | "root" | "err" | "report" | "level");
            if !is_keyword && forked.is_empty() {
                let ident: Ident = input.parse()?;
                Some(ComponentName::Ident(ident))
            } else {
                None
            }
        } else {
            None
        };

        let mut elements = Vec::new();
        if !input.is_empty() {
            let parsed: Punctuated<Element, Token![,]> = Punctuated::parse_terminated(input)?;
            elements = parsed.into_iter().collect();
        }

        Ok(InstrumentArgs { component, elements })
    }
}

// ── Result-return detection ───────────────────────────────────────────────────

/// Returns `true` when the function's outermost return type is `Result<…>`.
///
/// The check inspects the AST directly: it succeeds only when the return type
/// is a [`Type::Path`] whose last segment is literally named `Result`.  This
/// avoids the false positive produced by a plain string-contains search (e.g.
/// a type named `NotAResult` would previously pass).
///
/// `async fn` is handled transparently: `syn` represents the declared return
/// type (before desugaring to `impl Future`) directly, so `async fn foo() ->
/// Result<T,E>` has `sig.output = Result<T,E>` just like its sync equivalent.
fn has_result_return_type(item: &ItemFn) -> bool {
    let ty = match &item.sig.output {
        ReturnType::Default => return false,
        ReturnType::Type(_, ty) => ty.as_ref(),
    };

    let Type::Path(type_path) = ty else {
        return false;
    };

    type_path
        .path
        .segments
        .last()
        .is_some_and(|PathSegment { ident, .. }| ident == "Result")
}

/// Returns an error when the return type is an `impl Future` or `Pin<Box<dyn
/// Future>>` — shapes that are not supported with `err` / `report` because the
/// body-wrapping codegen cannot `.await` the function body.
///
/// Plain `async fn` is **not** affected: its declared return type is the inner
/// `Result`, and `tracing::instrument` desugars it correctly.
fn reject_future_return_type(item: &ItemFn) -> syn::Result<()> {
    let ty = match &item.sig.output {
        ReturnType::Default => return Ok(()),
        ReturnType::Type(_, ty) => ty.as_ref(),
    };

    // `impl Future<Output = …>` — syn represents this as Type::ImplTrait.
    if let Type::ImplTrait(TypeImplTrait { .. }) = ty {
        return Err(syn::Error::new(
            ty.span(),
            "`err` / `report` is not supported on `impl Future` return types; \
             use `async fn` instead",
        ));
    }

    // `Pin<Box<dyn Future<…>>>` or any other outer wrapper — heuristic: check
    // whether the return type is *not* a bare `Result` path and contains a
    // `dyn` trait object somewhere (Type::TraitObject nested inside).
    //
    // We only emit the error when the outermost path does NOT end in `Result`
    // to avoid false positives, and the function is not async (which would be
    // fine).  The check is intentionally conservative: we only flag the
    // `Pin<Box<dyn …>>` idiom, not every non-Result path (those are rejected
    // later by `has_result_return_type`).
    if item.sig.asyncness.is_none() {
        if let Type::Path(tp) = ty {
            if let Some(seg) = tp.path.segments.last() {
                if seg.ident != "Result" {
                    if type_contains_dyn(ty) {
                        return Err(syn::Error::new(
                            ty.span(),
                            "`err` / `report` is not supported on `Box<dyn Future>` return types; \
                             use `async fn` instead",
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

/// Recursively checks whether a type contains a `dyn Trait` object.
fn type_contains_dyn(ty: &Type) -> bool {
    match ty {
        Type::TraitObject(_) => true,
        Type::Path(tp) => tp.path.segments.iter().any(|seg| {
            if let syn::PathArguments::AngleBracketed(ab) = &seg.arguments {
                ab.args.iter().any(|arg| {
                    if let syn::GenericArgument::Type(inner) = arg {
                        type_contains_dyn(inner)
                    } else {
                        false
                    }
                })
            } else {
                false
            }
        }),
        Type::Reference(r) => type_contains_dyn(&r.elem),
        _ => false,
    }
}

// ── codegen helpers ───────────────────────────────────────────────────────────

/// Builds one token pair per field: `dotted.name = [%] expr`.
fn field_parts(fields: &[&Field]) -> Vec<TokenStream2> {
    FromIterator::from_iter(fields.iter().map(|f| {
        let name_tokens = TokenStream2::from_str(&f.name.dotted)
            .unwrap_or_else(|_| panic!("invalid field name: {}", f.name.dotted));
        let expr = &f.value.expr;
        if f.value.display_modifier.is_some() {
            quote! { #name_tokens = %#expr }
        } else {
            quote! { #name_tokens = #expr }
        }
    }))
}

/// Wraps [`field_parts`] in `fields(…),` for use in `#[tracing::instrument(…)]`.
fn fields_tokens(fields: &[&Field]) -> TokenStream2 {
    let parts = field_parts(fields);
    if parts.is_empty() {
        quote! {}
    } else {
        quote! { fields(#(#parts),*), }
    }
}

/// Prepends an optional `ret = Empty` entry to [`field_parts`] and returns the
/// result as `, field, …` for appending directly after the span name in `span!`.
fn inline_fields_tokens(fields: &[&Field], has_ret: bool) -> TokenStream2 {
    let ret = has_ret.then(|| quote! { ret = ::tracing::field::Empty });
    let parts: Vec<_> = FromIterator::from_iter(ret.into_iter().chain(field_parts(fields)));
    if parts.is_empty() {
        quote! {}
    } else {
        quote! { , #(#parts),* }
    }
}

// ── ident-component codegen ───────────────────────────────────────────────────

/// Code generation for [`ComponentName::Ident`].
///
/// Uses `::tracing::span!(target: IDENT, …)` directly so the component const's
/// runtime value (e.g. `"miden-block-producer"`) is used as the OTel target rather
/// than the identifier name `"COMPONENT"` that `tracing::instrument(target = "IDENT")`
/// would bake in.
///
/// Sync functions use `let _guard = __span.enter()`.
/// Async functions wrap the body with `async move { … }.instrument(__span).await`.
fn codegen_with_ident_component(
    component: &Ident,
    level: Option<&SpanLevel>,
    has_ret: bool,
    has_err: bool,
    has_report: bool,
    has_root: bool,
    fields: &[&Field],
    func: ItemFn,
) -> syn::Result<TokenStream2> {
    let ItemFn { attrs, vis, sig, block } = func;
    let is_async = sig.asyncness.is_some();

    let fn_name_lit = LitStr::new(&sig.ident.to_string(), sig.ident.span());

    let parent_arg = if has_root {
        quote! { parent: None, }
    } else {
        quote! {}
    };

    let inline_fields = inline_fields_tokens(fields, has_ret);

    let level_tok =
        level.map_or_else(|| quote! { ::tracing::Level::INFO }, SpanLevel::to_level_tokens);

    let span_tok = quote! {
        let __span = ::tracing::span!(target: crate::#component, #parent_arg #level_tok, #fn_name_lit #inline_fields);
    };

    let err_check = if has_err {
        quote! {
            if let ::core::result::Result::Err(ref __err) = __result {
                ::tracing::error!(error = %__err);
            }
        }
    } else {
        quote! {}
    };

    let report_check = if has_report {
        quote! {
            if let ::core::result::Result::Err(ref __err) = __result {
                use ::miden_node_utils::ErrorReport as _;
                let __report = __err.as_report();
                ::tracing::error!(error = %__report);
                use ::miden_node_utils::tracing::OpenTelemetrySpanExt as _;
                ::tracing::Span::current().set_error(__err as &dyn ::std::error::Error);
            }
        }
    } else {
        quote! {}
    };

    let ret_record = if has_ret {
        if has_err || has_report {
            // Only record on the Ok path; the Err path is handled by err_check / report_check.
            quote! {
                if let ::core::result::Result::Ok(ref __ok) = __result {
                    ::tracing::Span::current().record("ret", ::tracing::field::debug(__ok));
                }
            }
        } else {
            quote! {
                ::tracing::Span::current().record("ret", ::tracing::field::debug(&__result));
            }
        }
    } else {
        quote! {}
    };

    let needs_binding = has_ret || has_err || has_report;

    if is_async {
        if needs_binding {
            Ok(quote! {
                #(#attrs)*
                #vis #sig {
                    use ::tracing::Instrument as _;
                    #span_tok
                    async move {
                        let __result = #block;
                        #[allow(unreachable_code)] {
                            #err_check
                            #report_check
                            #ret_record
                            __result
                        }
                    }.instrument(__span).await
                }
            })
        } else {
            Ok(quote! {
                #(#attrs)*
                #vis #sig {
                    use ::tracing::Instrument as _;
                    #span_tok
                    async move #block .instrument(__span).await
                }
            })
        }
    } else if needs_binding {
        Ok(quote! {
            #(#attrs)*
            #vis #sig {
                #span_tok
                let _guard = __span.enter();
                let __result = #block;
                #[allow(unreachable_code)] {
                    #err_check
                    #report_check
                    #ret_record
                    __result
                }
            }
        })
    } else {
        Ok(quote! {
            #(#attrs)*
            #vis #sig {
                #span_tok
                let _guard = __span.enter();
                #block
            }
        })
    }
}

// ── public entry point ────────────────────────────────────────────────────────

/// Core implementation of `#[instrument]`.
///
/// # Validation
///
/// | Condition | Error |
/// |---|---|
/// | `err` and `report` both present | mutually exclusive |
/// | `err` or `report` on a non-`Result` fn | `err`/`report` requires `Result` return |
/// | `ret` + `report` on a non-`Result` fn | same |
/// | field name not in `allowlist.txt` | open telemetry allowlist violation |
///
/// # Code generation
///
/// For `ComponentName::Ident`, delegates to [`codegen_with_ident_component`] which uses
/// `::tracing::span!` directly so the const's runtime value is used as the target.
///
/// For `ComponentName::Literal` or no component, two output shapes:
///
/// **`report` present**
/// ```rust,ignore
/// #[::tracing::instrument(target = "…", skip_all, fields(…), ret?)]
/// fn foo(…) -> Result<T, E> {
///     let __result: Result<T, E> = { /* original body */ };
///     if let Err(ref __err) = __result {
///         use ::miden_node_utils::ErrorReport as _;
///         ::tracing::error!(error = %__err.as_report());
///         use ::miden_node_utils::tracing::OpenTelemetrySpanExt as _;
///         ::tracing::Span::current().set_error(__err as &dyn ::std::error::Error);
///     }
///     __result
/// }
/// ```
///
/// **`err` or neither**
/// ```rust,ignore
/// #[::tracing::instrument(target = "…", skip_all, fields(…), ret?, err?)]
/// fn foo(…) { /* original body */ }
/// ```
pub fn instrument2(attr: TokenStream2, item: TokenStream2) -> syn::Result<TokenStream2> {
    // Fast path: empty attribute stream → plain delegation, no validation needed.
    if attr.is_empty() {
        let func: ItemFn = syn::parse2(item)?;
        let ItemFn { attrs, vis, sig, block } = func;
        return Ok(quote! {
            #(#attrs)*
            #[::tracing::instrument]
            #vis #sig #block
        });
    }

    let args: InstrumentArgs = syn::parse2(attr)?;
    let func: ItemFn = syn::parse2(item)?;

    // ── collect element kinds ──────────────────────────────────────────────────
    let mut has_ret = false;
    let mut has_err = false;
    let mut has_report = false;
    let mut has_root = false;
    let mut level: Option<SpanLevel> = None;
    let mut fields: Vec<&Field> = Vec::new();

    let elements = args.elements;

    for elem in &elements {
        match elem {
            Element::Ret => has_ret = true,
            Element::Root => has_root = true,
            Element::Err => has_err = true,
            Element::Report => has_report = true,
            Element::Level(l) => {
                if level.is_some() {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        "level specified more than once",
                    ));
                }
                level = Some(l.clone());
            },
            Element::Field(f) => fields.push(f.as_ref()),
        }
    }

    // ── validation ────────────────────────────────────────────────────────────

    // err and report are mutually exclusive.
    if has_err && has_report {
        return Err(syn::Error::new(
            Span::call_site(),
            "`err` and `report` are mutually exclusive – use one or the other",
        ));
    }

    // Reject unsupported future-returning shapes before the Result check.
    if has_err || has_report {
        reject_future_return_type(&func)?;
    }

    // err / report require a Result return type.
    if (has_err || has_report) && !has_result_return_type(&func) {
        return Err(syn::Error::new(
            func.sig.ident.span(),
            "`err` / `report` requires the function to return `Result`",
        ));
    }

    // Field names were already validated inside Field::parse via Name::check.

    // ── code generation ───────────────────────────────────────────────────────

    // For ComponentName::Ident, use span! directly so the component const's runtime value
    // (e.g. "miden-block-producer") is used as the target rather than the identifier name
    // "COMPONENT" that tracing::instrument would bake in as a string literal.
    if let Some(ComponentName::Ident(component_ident)) = &args.component {
        return codegen_with_ident_component(
            component_ident,
            level.as_ref(),
            has_ret,
            has_err,
            has_report,
            has_root,
            &fields,
            func,
        );
    }

    let level_tok = level.as_ref().map(|l| {
        let s = l.as_str();
        let lit = LitStr::new(s, Span::call_site());
        quote! { level = #lit, }
    });
    let target_tokens = args.component.as_ref().map(|c| {
        // Ident components are handled above by the early-return into codegen_with_ident_component.
        let ComponentName::Literal(lit) = c else { unreachable!() };
        quote! { target = #lit, }
    });
    let name_tokens = args.component.as_ref().map(|c| {
        let name = format!("{}.{}", c.as_string(), func.sig.ident);
        let lit = LitStr::new(&name, func.sig.ident.span());
        quote! { name = #lit, }
    });
    let fields_tok = fields_tokens(&fields);

    // Always skip all implicit fn arguments to avoid accidentally recording sensitive values.
    // Explicit OTel fields declared in the attribute are still emitted via `fields(…)`.
    let skip_all = quote! { skip_all, };

    let parent_tok = if has_root {
        quote! { parent = None, }
    } else {
        quote! {}
    };

    let ret_tok = if has_ret {
        quote! { ret, }
    } else {
        quote! {}
    };

    let ItemFn { attrs, vis, sig, block } = func;

    if has_report {
        let result_ty = match &sig.output {
            ReturnType::Type(_, ty) => quote! { #ty },
            ReturnType::Default => quote! { () },
        };
        Ok(quote! {
            #(#attrs)*
            #[::tracing::instrument(#level_tok #parent_tok #target_tokens #name_tokens #skip_all #fields_tok #ret_tok)]
            #vis #sig {
                let __result: #result_ty = #block;
                if let ::core::result::Result::Err(ref __err) = __result {
                    use ::miden_node_utils::ErrorReport as _;
                    let __report = __err.as_report();
                    ::tracing::error!(error = %__report);
                    use ::miden_node_utils::tracing::OpenTelemetrySpanExt as _;
                    ::tracing::Span::current().set_error(__err as &dyn ::std::error::Error);
                }
                __result
            }
        })
    } else {
        let err_tok = if has_err {
            quote! { err }
        } else {
            quote! {}
        };
        Ok(quote! {
            #(#attrs)*
            #[::tracing::instrument(#level_tok #parent_tok #target_tokens #name_tokens #skip_all #fields_tok #ret_tok #err_tok)]
            #vis #sig #block
        })
    }
}
