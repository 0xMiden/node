use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{Expr, Ident, ItemFn, LitStr, PathSegment, ReturnType, Token, Type};

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
        self.segments.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(".")
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
///
/// Parsing priority: the three reserved keywords (`ret`, `err`, `report`) are
/// recognised by peeking at the leading identifier before attempting a full
/// `Field` parse.  Any other leading identifier is treated as the start of a
/// `name = value` field entry.
enum Element {
    /// A `dotted-name = [%] expr` field (validated against the OpenTelemetry allowlist).
    Field(Field),
    /// `ret` – record the function's return value inside the span.
    Ret,
    /// `err` – on `Err`, emit a tracing event with the top-level error message.
    /// Delegates to `tracing::instrument`'s built-in `err`.  Requires `Result`.
    Err,
    /// `report` – on `Err`, walk the full error chain via [`ErrorReport`] and set
    /// the OpenTelemetry span status.  Mutually exclusive with `err`.  Requires `Result`.
    Report,
}

impl Parse for Element {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let forked: Ident = input.fork().parse()?;
        match forked.to_string().as_str() {
            "ret" => {
                let _: Ident = input.parse()?;
                Ok(Element::Ret)
            },
            "err" => {
                let _: Ident = input.parse()?;
                Ok(Element::Err)
            },
            "report" => {
                let _: Ident = input.parse()?;
                Ok(Element::Report)
            },
            _ => {
                let field: Field = input.parse()?;
                Ok(Element::Field(field))
            },
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
    /// Emits `target = "…",` for use in `#[tracing::instrument(…)]`.
    pub(crate) fn to_span_target_tokens(&self) -> TokenStream2 {
        match self {
            ComponentName::Literal(lit) => quote! { target = #lit, },
            ComponentName::Ident(ident) => {
                let s = ident.to_string();
                let lit = LitStr::new(&s, ident.span());
                quote! { target = #lit, }
            },
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
///                  | element ("," element)*
///
/// COMPONENT  ::= ident | string-literal
/// element    ::= field-entry | "ret" | "err" | "report"
/// field-entry::= dotted-name "=" ["%"] expr
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
        let component = if input.peek(LitStr) && input.peek2(Token![:]) {
            let lit: LitStr = input.parse()?;
            let _colon: Token![:] = input.parse()?;
            Some(ComponentName::Literal(lit))
        } else if input.peek(Ident) && input.peek2(Token![:]) {
            let ident: Ident = input.parse()?;
            let _colon: Token![:] = input.parse()?;
            Some(ComponentName::Ident(ident))
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
        .map(|PathSegment { ident, .. }| ident == "Result")
        .unwrap_or(false)
}

// ── codegen helpers ───────────────────────────────────────────────────────────

/// Converts the collected `Field` entries into a `fields(…),` token fragment.
///
/// Each field is emitted as `"dotted.name" = [%] expr`.  The string-literal form
/// is used for the key so that dotted names (which are not valid Rust identifiers)
/// survive the `tracing::instrument` macro's own field-name parsing.
fn fields_tokens(fields: &[&Field]) -> TokenStream2 {
    if fields.is_empty() {
        return quote! {};
    }
    let mut parts = Vec::new();
    for f in fields {
        let name_lit = LitStr::new(&f.name.dotted, f.name.span);
        let expr = &f.value.expr;
        if f.value.display_modifier.is_some() {
            parts.push(quote! { #name_lit = %#expr });
        } else {
            parts.push(quote! { #name_lit = #expr });
        }
    }
    quote! { fields(#(#parts),*), }
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
/// Three distinct output shapes depending on which keywords are present:
///
/// **`report` present**
/// ```rust,ignore
/// #[::tracing::instrument(target = …, skip_all, fields(…), ret?)]
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
/// **`err` present (no `report`)**
/// ```rust,ignore
/// #[::tracing::instrument(target = …, skip_all, fields(…), ret?, err)]
/// fn foo(…) -> Result<T, E> { /* original body */ }
/// ```
///
/// **Neither `err` nor `report`**
/// ```rust,ignore
/// #[::tracing::instrument(target = …, skip_all?, fields(…)?, ret?)]
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
    let mut fields: Vec<&Field> = Vec::new();

    let elements = args.elements;

    for elem in &elements {
        match elem {
            Element::Ret => has_ret = true,
            Element::Err => has_err = true,
            Element::Report => has_report = true,
            Element::Field(f) => fields.push(f),
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

    // err / report require a Result return type.
    if (has_err || has_report) && !has_result_return_type(&func) {
        return Err(syn::Error::new(
            func.sig.ident.span(),
            "`err` / `report` requires the function to return `Result`",
        ));
    }

    // Field names were already validated inside Field::parse via Name::check.

    // ── code generation ───────────────────────────────────────────────────────

    let target_tokens = args.component.as_ref().map(ComponentName::to_span_target_tokens);
    let fields_tok = fields_tokens(&fields);

    // When explicit fields are present, skip all implicit fn arguments to avoid
    // accidentally recording sensitive values.
    let skip_all = if !fields.is_empty() {
        quote! { skip_all, }
    } else {
        quote! {}
    };

    let ret_tok = if has_ret {
        quote! { ret, }
    } else {
        quote! {}
    };

    let ItemFn { attrs, vis, sig, block } = func;
    let result_ty = match &sig.output {
        ReturnType::Type(_, ty) => quote! { #ty },
        ReturnType::Default => quote! { () },
    };

    if has_report {
        // Wrap the original body so we can inspect the result before returning.
        // On Err: emit the full error chain and mark the OpenTelemetry span as failed.
        Ok(quote! {
            #(#attrs)*
            #[::tracing::instrument(#target_tokens #skip_all #fields_tok #ret_tok)]
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
    } else if has_err {
        // Delegate to tracing::instrument's built-in err support.
        Ok(quote! {
            #(#attrs)*
            #[::tracing::instrument(#target_tokens #skip_all #fields_tok #ret_tok err)]
            #vis #sig #block
        })
    } else {
        // No error-reporting variant – plain span wrapper.
        Ok(quote! {
            #(#attrs)*
            #[::tracing::instrument(#target_tokens #skip_all #fields_tok #ret_tok)]
            #vis #sig #block
        })
    }
}
