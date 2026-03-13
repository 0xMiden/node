use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{Expr, Ident, ItemFn, LitStr, ReturnType, Token};

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

// ── Value ─────────────────────────────────────────────────────────────────────

/// The right-hand side of a field assignment: an optional `%` Display modifier
/// followed by an arbitrary expression.
///
/// - `= expr`  → Debug format (`{:?}`)
/// - `= %expr` → Display format (`{}`)
struct Value {
    display_modifier: Option<Token![%]>,
    expr: Expr,
}

impl Parse for Value {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let display_modifier = input.parse::<Token![%]>().ok();
        let expr = input.parse::<Expr>()?;
        Ok(Value { display_modifier, expr })
    }
}

// ── Field entry ───────────────────────────────────────────────────────────────

/// A single `dotted-name = [%] expr` pair inside the attribute list.
///
/// The `name` is validated against the OTel allowlist before code is emitted.
/// Both `account.id = id` (Debug) and `account.id = %id` (Display) are accepted.
struct Field {
    name: Name,
    _eq: Token![=],
    value: Value,
}

impl Parse for Field {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Field {
            name: input.parse()?,
            _eq: input.parse()?,
            value: input.parse()?,
        })
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
    /// A `dotted-name = [%] expr` field (validated against the OTel allowlist).
    Field(Field),
    /// `ret` – record the function's return value inside the span.
    Ret,
    /// `err` – on `Err`, emit a tracing event with the top-level error message.
    /// Delegates to `tracing::instrument`'s built-in `err`.  Requires `Result`.
    Err,
    /// `report` – on `Err`, walk the full error chain via [`ErrorReport`] and set
    /// the OTel span status.  Mutually exclusive with `err`.  Requires `Result`.
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
/// ```text
/// #[instrument(RPC: …)]          → Ident("rpc")   → target = RPC
/// #[instrument("my-rpc": …)]     → Literal("my-rpc") → target = "my-rpc"
/// ```
enum ComponentName {
    Literal(LitStr),
    Ident(Ident),
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

// ── Returns-Result helper ─────────────────────────────────────────────────────

/// Returns `true` if the function's return type token stream contains the word
/// `Result`. Syntactic check only without any type resolution!
fn returns_result(item: &ItemFn) -> bool {
    match &item.sig.output {
        ReturnType::Default => false,
        ReturnType::Type(_, ty) => {
            let s = quote! { #ty }.to_string();
            s.contains("Result") // TODO be more accurate here what we support
        },
    }
}

// ── allowlist check ───────────────────────────────────────────────────────────

/// Validates `name` against the OTel field allowlist (`allowlist.txt`).
///
/// On failure, emits a [`syn::Error`] anchored at the name's span.  If the
/// fuzzy-search backend finds close matches in the allowlist they are included in
/// the error message as suggestions.
fn check_allowlist(name: &Name) -> syn::Result<()> {
    crate::allowed::check(name).map_err(|suggestions| {
        let dotted = name.to_dotted_string();
        let hint = if suggestions.is_empty() {
            String::new()
        } else {
            format!(" – did you mean: {}?", suggestions.join(", "))
        };
        syn::Error::new(
            name.span(),
            format!("`{dotted}` is not in the open telemetry allowlist: {hint}"),
        )
    })
}

// ── codegen helpers ───────────────────────────────────────────────────────────

/// Converts the optional component into a `target = "…",` token fragment for
/// insertion into `#[tracing::instrument(…)]`.  Returns `None` when no component
/// was specified so that `tracing` falls back to the default (module path).
fn component_target(component: &Option<ComponentName>) -> Option<TokenStream2> {
    match component {
        Some(ComponentName::Literal(lit)) => Some(quote! { target = #lit, }),
        Some(ComponentName::Ident(ident)) => {
            let s = ident.to_string();
            let lit = LitStr::new(&s, ident.span());
            Some(quote! { target = #lit, })
        },
        None => None,
    }
}

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
        let name_str = f.name.to_dotted_string();
        let name_lit = LitStr::new(&name_str, f.name.span());
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

    let args: InstrumentArgs = syn::parse2(attr.clone())?;
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
    if (has_err || has_report) && !returns_result(&func) {
        return Err(syn::Error::new(
            func.sig.ident.span(),
            "`err` / `report` requires the function to return `Result`",
        ));
    }

    // ret alone is valid on any fn; ret + report still needs Result (already covered
    // by the check above when has_report is true).
    if has_ret && has_report && !returns_result(&func) {
        return Err(syn::Error::new(
            func.sig.ident.span(),
            "`ret` + `report` requires the function to return `Result`",
        ));
    }

    // Validate every field name against the allowlist.
    for f in &fields {
        check_allowlist(&f.name)?;
    }

    // ── code generation ───────────────────────────────────────────────────────

    let target_tokens = component_target(&args.component);
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
        // On Err: emit the full error chain and mark the OTel span as failed.
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
