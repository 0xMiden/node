use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{Expr, Ident, LitStr, Token};

use crate::instrument::{CheckedName, ComponentName, Name};

// ── LogField ─────────────────────────────────────────────────────────────────

/// A single `dotted-name = [% | ?] expr` structured field in a log event.
///
/// Both the `%` (Display) and `?` (Debug) value modifiers are accepted, matching
/// `tracing`'s own syntax.  The field name is validated against the OpenTelemetry allowlist
/// at parse time via [`Name::check`].
struct LogField {
    name: CheckedName,
    /// Raw tokens for the value, including the optional `%`/`?` prefix.  We
    /// preserve these verbatim so `tracing` can interpret them itself.
    value_tokens: TokenStream2,
}

impl Parse for LogField {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let raw: Name = input.parse()?;
        let name = raw.check()?;
        let _eq: Token![=] = input.parse()?;

        // Collect the optional modifier (`%` or `?`) plus the value expression as
        // a token stream so we can forward it unchanged to `tracing::<level>!`.
        let mut value_tokens = TokenStream2::new();
        if input.peek(Token![%]) {
            let tok: Token![%] = input.parse()?;
            value_tokens.extend(quote! { #tok });
        } else if input.peek(Token![?]) {
            let tok: Token![?] = input.parse()?;
            value_tokens.extend(quote! { #tok });
        }
        let expr: Expr = input.parse()?;
        value_tokens.extend(quote! { #expr });

        Ok(LogField { name, value_tokens })
    }
}

// ── LogArgs ───────────────────────────────────────────────────────────────────

/// Parsed representation of a log-macro call.
///
/// Grammar:
/// ```text
/// LogArgs ::= ε
///           | COMPONENT ":" [field-entry ","]* [message]
///           | [field-entry ","]* [message]
///
/// COMPONENT   ::= ident | string-literal
/// field-entry ::= dotted-name "=" ["%" | "?"] expr
/// message     ::= string-literal ["," expr]*
/// ```
///
/// The `COMPONENT:` prefix maps to `target: "component"` in the emitted
/// `tracing::<level>!` call.  Field names are validated against the OpenTelemetry
/// allowlist at parse time.  The trailing message (if any) is forwarded verbatim.
struct LogArgs {
    /// Optional component prefix; emitted as `target: "…"` in the tracing call.
    component: Option<ComponentName>,
    /// Structured fields, allowlist-validated at parse time.
    fields: Vec<LogField>,
    /// Remaining tokens after the last field – the message string and any format
    /// arguments, forwarded verbatim to `tracing`.
    message_tokens: TokenStream2,
}

impl Parse for LogArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.is_empty() {
            return Ok(LogArgs {
                component: None,
                fields: Vec::new(),
                message_tokens: quote! {},
            });
        }

        // Detect optional `COMPONENT:` prefix: ident or string literal followed by `:`.
        // Must not be mistaken for `field = value` (those use `=` not `:`).
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

        // Parse comma-separated fields.  We stop at the first token that cannot
        // start a field: a string literal marks the beginning of the message.
        //
        // A field starts with an ident (the first segment of a dotted name) and
        // must be followed at some point by `=`.  We use a forked parse to check
        // whether the next comma-delimited token is a field or the message.
        let mut fields: Vec<LogField> = Vec::new();

        loop {
            if input.is_empty() {
                break;
            }
            // A string literal cannot be a field name → it starts the message.
            if input.peek(LitStr) {
                break;
            }
            // Try to parse a field: `name = …`.  If the lookahead shows an ident
            // but no `=` follows the name, it's not a field either (bare ident
            // expressions are not supported as log messages here).
            //
            // We fork so that a failed parse doesn't consume input.
            let forked = input.fork();
            if forked.parse::<Name>().is_ok() && forked.peek(Token![=]) {
                let field: LogField = input.parse()?;
                fields.push(field);
                // Consume the trailing comma, if any.
                if input.peek(Token![,]) {
                    let _: Token![,] = input.parse()?;
                }
            } else {
                // Not a field – the rest is the message.
                break;
            }
        }

        // Everything that remains (message string + format args) is forwarded
        // verbatim.
        let message_tokens: TokenStream2 = input.parse()?;

        Ok(LogArgs { component, fields, message_tokens })
    }
}

// ── public entry point ────────────────────────────────────────────────────────

/// Parses and validates a log-macro call, then expands it to
/// `::tracing::event!(target: "…", Level::LEVEL, field = value, …, "message", …)`.
///
/// [`tracing::event!`] is used instead of the level-specific macros (`warn!`, `info!`, …)
/// because those macros only accept ident keys when `target:` is present, rejecting the
/// string-literal dotted keys we emit (e.g. `"account.id"`).  `event!` has a more permissive
/// parser that accepts string literal keys in all argument positions.
///
/// Called by all five log proc-macros (`error!`, `warn!`, `info!`, `debug!`, `trace!`).
pub(crate) fn parse(level: &'static str, ts: TokenStream2) -> syn::Result<TokenStream2> {
    let args: LogArgs = syn::parse2(ts)?;

    // `tracing::Level` variant matching the requested level.
    let level_variant = syn::Ident::new(&level.to_uppercase(), proc_macro2::Span::call_site());

    // Build the target fragment (present only when a component was given).
    let target_tok = args.component.as_ref().map(ComponentName::to_event_target_tokens);

    // Build the field fragments: `"dotted.name" = [%|?] expr`.
    let field_toks: Vec<TokenStream2> = args
        .fields
        .iter()
        .map(|f| {
            let name_lit = LitStr::new(&f.name.dotted, f.name.span);
            let val = &f.value_tokens;
            quote! { #name_lit = #val }
        })
        .collect();

    // Emit trailing comma between fields and message only when both are present.
    let msg = &args.message_tokens;
    let sep = if !field_toks.is_empty() && !msg.is_empty() {
        quote! { , }
    } else {
        quote! {}
    };

    Ok(quote! {
        ::tracing::event!(#target_tok ::tracing::Level::#level_variant, #(#field_toks),* #sep #msg)
    })
}
