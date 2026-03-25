use proc_macro2::TokenStream as TokenStream2;
use quote::quote;

use crate::instrument::instrument2;
use crate::log;

fn warn2(ts: TokenStream2) -> syn::Result<TokenStream2> {
    log::parse("warn", ts)
}

fn error2(ts: TokenStream2) -> syn::Result<TokenStream2> {
    log::parse("error", ts)
}

fn info2(ts: TokenStream2) -> syn::Result<TokenStream2> {
    log::parse("info", ts)
}

fn debug2(ts: TokenStream2) -> syn::Result<TokenStream2> {
    log::parse("debug", ts)
}

fn trace2(ts: TokenStream2) -> syn::Result<TokenStream2> {
    log::parse("trace", ts)
}

/// A function whose return type *contains* the word "Result" but is not `Result`.
/// The old string-contains check would incorrectly accept this.
fn item_fake_result_fn() -> TokenStream2 {
    quote! { fn foo() -> NotAResult { NotAResult } }
}

// ── item fixtures ─────────────────────────────────────────────────────────────

/// Plain function, does not return a Result.
fn item_bare_fn() -> TokenStream2 {
    quote! { fn foo() {} }
}

/// Function returning Result<(), String> – Ok type is unit (no Display needed).
fn item_result_unit_fn() -> TokenStream2 {
    quote! { fn foo() -> Result<(), String> { Ok(()) } }
}

/// Function returning Result<u32, String> – Ok type implements Display.
fn item_result_display_fn() -> TokenStream2 {
    quote! { fn foo() -> Result<u32, String> { Ok(42) } }
}

// ── #[instrument]  /  #[instrument()] ────────────────────────────────────────

#[test]
fn instrument_bare_succeeds() {
    // #[instrument]  –  empty attr stream, any fn  →  ok
    let result = instrument2(quote! {}, item_bare_fn());
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn instrument_empty_parens_succeeds() {
    // #[instrument()]  –  rustc strips the outer parens before the proc-macro sees the stream,
    // so the attr stream is empty – identical to the bare case above.
    let result = instrument2(quote! {}, item_bare_fn());
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn instrument_component_prefixes_span_name() {
    let result = instrument2(quote! { rpc: }, item_bare_fn()).expect("expansion should succeed");
    let tokens = result.to_string();
    assert!(tokens.contains("name = \"rpc.foo\""), "{tokens}");
}

#[test]
fn instrument_component_prefixes_span_name_for_report() {
    let result = instrument2(quote! { rpc: report }, item_result_unit_fn())
        .expect("expansion should succeed");
    let tokens = result.to_string();
    assert!(tokens.contains("name = \"rpc.foo\""), "{tokens}");
}

#[test]
fn instrument_component_prefixes_span_name_for_err() {
    let result =
        instrument2(quote! { rpc: err }, item_result_unit_fn()).expect("expansion should succeed");
    let tokens = result.to_string();
    assert!(tokens.contains("name = \"rpc.foo\""), "{tokens}");
}

// ── report ────────────────────────────────────────────────────────────────────

#[test]
fn instrument_report_on_result_fn_succeeds() {
    // #[instrument(rpc: report)]  –  fn returns Result  →  ok
    let result = instrument2(quote! { rpc: report }, item_result_unit_fn());
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn instrument_report_on_bare_fn_fails() {
    // #[instrument(rpc: report)]  –  fn does NOT return Result  →  error
    let result = instrument2(quote! { rpc: report }, item_bare_fn());
    assert!(result.is_err(), "{result:?}");
}

// ── err ───────────────────────────────────────────────────────────────────────

#[test]
fn instrument_err_on_result_fn_succeeds() {
    // #[instrument(rpc: err)]  –  fn returns Result  →  ok
    let result = instrument2(quote! { rpc: err }, item_result_unit_fn());
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn instrument_err_on_bare_fn_fails() {
    // #[instrument(rpc: err)]  –  fn does NOT return Result  →  error
    let result = instrument2(quote! { rpc: err }, item_bare_fn());
    assert!(result.is_err(), "{result:?}");
}

// ── report, err  (mutually exclusive) ────────────────────────────────────────

#[test]
fn instrument_report_err_fails() {
    // #[instrument(rpc: report, err)]  –  mutually exclusive  →  error
    let result = instrument2(quote! { rpc: report, err }, item_result_unit_fn());
    assert!(result.is_err(), "{result:?}");
}

#[test]
fn instrument_err_report_fails() {
    // #[instrument(rpc: err, report)]  –  same constraint, reversed order  →  error
    let result = instrument2(quote! { rpc: err, report }, item_result_unit_fn());
    assert!(result.is_err(), "{result:?}");
}

// ── ret ───────────────────────────────────────────────────────────────────────

#[test]
fn instrument_ret_succeeds() {
    // #[instrument(rpc: ret)]  –  any fn  →  ok  (no Result required)
    let result = instrument2(quote! { rpc: ret }, item_bare_fn());
    assert!(result.is_ok(), "{result:?}");
}

// ── ret, report ───────────────────────────────────────────────────────────────

#[test]
fn instrument_ret_report_on_result_display_fn_succeeds() {
    // #[instrument(rpc: ret, report)]
    //   fn returns Result  AND  Ok: Display  →  ok
    //   (Display on Ok is a call-site constraint; the macro accepts the syntax)
    let result = instrument2(quote! { rpc: ret, report }, item_result_display_fn());
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn instrument_ret_report_on_bare_fn_fails() {
    // #[instrument(rpc: ret, report)]  –  fn does NOT return Result  →  error
    let result = instrument2(quote! { rpc: ret, report }, item_bare_fn());
    assert!(result.is_err(), "{result:?}");
}

// ── allowlisted field = value ─────────────────────────────────────────────────

#[test]
fn instrument_allowlisted_field_eq_value_succeeds() {
    // #[instrument(rpc: account.id = bar)]  –  account.id is in the allowlist  →  ok
    let result = instrument2(quote! { rpc: account.id = bar }, item_bare_fn());
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn instrument_unlisted_field_eq_value_fails() {
    // #[instrument(rpc: foo = bar)]  –  foo NOT in allowlist  →  error
    let result = instrument2(quote! { rpc: foo = bar }, item_bare_fn());
    assert!(result.is_err(), "{result:?}");
}

// ── allowlisted field = %value  (Display modifier) ───────────────────────────

#[test]
fn instrument_allowlisted_field_display_value_succeeds() {
    // #[instrument(rpc: account.id = %bar)]  –  account.id allowlisted, % modifier  →  ok
    let result = instrument2(quote! { rpc: account.id = %bar }, item_bare_fn());
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn instrument_allowlisted_field_debug_explicit_value_succeeds() {
    // #[instrument(rpc: account.id = ?bar)]  –  account.id allowlisted, ? modifier  →  ok
    let result = instrument2(quote! { rpc: account.id = ?bar }, item_bare_fn());
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn instrument_unlisted_field_display_value_fails() {
    // #[instrument(rpc: foo.bar.baz = %bar)]  –  foo.bar.baz NOT in allowlist  →  error
    let result = instrument2(quote! { rpc: foo.bar.baz = %bar }, item_bare_fn());
    assert!(result.is_err(), "{result:?}");
}

// ── combined: allowlisted fields + err/report ─────────────────────────────────

#[test]
fn instrument_allowlisted_field_display_err_on_result_fn_succeeds() {
    // #[instrument(rpc: account.id = %bar, err)]
    //   allowlisted + % + err + Result  →  ok
    let result = instrument2(quote! { rpc: account.id = %bar, err }, item_result_unit_fn());
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn instrument_allowlisted_field_display_report_on_result_fn_succeeds() {
    // #[instrument(rpc: nullifier.id = %bar, report)]
    //   allowlisted + % + report + Result  →  ok
    let result = instrument2(quote! { rpc: nullifier.id = %bar, report }, item_result_unit_fn());
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn instrument_allowlisted_field_display_ret_report_on_result_display_fn_succeeds() {
    // #[instrument(rpc: account.id = %bar, ret, report)]
    //   allowlisted + % + ret + report + Result<Display, _>  →  ok
    let result =
        instrument2(quote! { rpc: account.id = %bar, ret, report }, item_result_display_fn());
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn instrument_unlisted_field_display_err_on_result_fn_fails() {
    // #[instrument(rpc: foo = bar, err)]  –  foo NOT in allowlist  →  error
    //   (allowlist check fires regardless of the presence of err)
    let result = instrument2(quote! { rpc: foo = bar, err }, item_result_unit_fn());
    assert!(result.is_err(), "{result:?}");
}

#[test]
fn instrument_allowlisted_field_display_report_err_fails() {
    // #[instrument(rpc: account.id = %bar, report, err)]
    //   allowlist ok, but report + err are mutually exclusive  →  error
    let result = instrument2(quote! { rpc: account.id = %bar, report, err }, item_result_unit_fn());
    assert!(result.is_err(), "{result:?}");
}

// ── warn! / log macros ────────────────────────────────────────────────────────

// ── empty / message only ──────────────────────────────────────────────────────

#[test]
fn warn_empty_succeeds() {
    // warn!()  –  empty stream  →  ok  (empty tracing event)
    let result = warn2(quote! {});
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn warn_message_only_succeeds() {
    // warn!("something odd")  –  plain string literal  →  ok
    let result = warn2(quote! { "something odd" });
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn warn_format_string_succeeds() {
    // warn!("retry after {}ms", delay)  –  format string  →  ok
    let result = warn2(quote! { "retry after {}ms", delay });
    assert!(result.is_ok(), "{result:?}");
}

// ── component ─────────────────────────────────────────────────────────────────

#[test]
fn warn_component_ident_message_succeeds() {
    // warn!(rpc: "msg")  –  component ident + message  →  ok
    let result = warn2(quote! { rpc: "msg" });
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn warn_component_literal_message_succeeds() {
    // warn!("block-producer": "msg")  –  string-literal component  →  ok
    let result = warn2(quote! { "block-producer": "msg" });
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn warn_component_only_succeeds() {
    // warn!(rpc:)  –  component with no fields or message  →  ok
    let result = warn2(quote! { rpc: });
    assert!(result.is_ok(), "{result:?}");
}

// ── allowlisted fields ────────────────────────────────────────────────────────

#[test]
fn warn_allowlisted_field_debug_succeeds() {
    // warn!(account.id = id, "msg")  –  allowlisted, Debug format  →  ok
    let result = warn2(quote! { account.id = id, "msg" });
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn warn_allowlisted_field_display_succeeds() {
    // warn!(account.id = %id, "msg")  –  allowlisted, Display format  →  ok
    let result = warn2(quote! { account.id = %id, "msg" });
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn warn_allowlisted_field_debug_explicit_succeeds() {
    // warn!(account.id = ?id, "msg")  –  allowlisted, explicit Debug  →  ok
    let result = warn2(quote! { account.id = ?id, "msg" });
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn warn_multiple_allowlisted_fields_succeeds() {
    // warn!(account.id = %id, block.number = n, "msg")  –  two allowlisted fields  →  ok
    let result = warn2(quote! { account.id = %id, block.number = n, "msg" });
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn warn_allowlisted_fields_no_message_succeeds() {
    // warn!(account.id = %id, block.number = n)  –  fields only, no message  →  ok
    let result = warn2(quote! { account.id = %id, block.number = n });
    assert!(result.is_ok(), "{result:?}");
}

// ── unlisted fields ───────────────────────────────────────────────────────────

#[test]
fn warn_unlisted_field_fails() {
    // warn!(foo = %x, "msg")  –  foo NOT in allowlist  →  error
    let result = warn2(quote! { foo = %x, "msg" });
    assert!(result.is_err(), "{result:?}");
}

#[test]
fn warn_unlisted_dotted_field_fails() {
    // warn!(foo.bar = %x, "msg")  –  foo.bar NOT in allowlist  →  error
    let result = warn2(quote! { foo.bar = %x, "msg" });
    assert!(result.is_err(), "{result:?}");
}

// ── component + fields ────────────────────────────────────────────────────────

#[test]
fn warn_component_allowlisted_field_message_succeeds() {
    // warn!(rpc: account.id = %id, "msg")  –  component + allowlisted + message  →  ok
    let result = warn2(quote! { rpc: account.id = %id, "msg" });
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn warn_component_unlisted_field_fails() {
    // warn!(rpc: foo = %x, "msg")  –  component present but foo NOT in allowlist  →  error
    // (allowlist applies regardless of component)
    let result = warn2(quote! { rpc: foo = %x, "msg" });
    assert!(result.is_err(), "{result:?}");
}

#[test]
fn warn_component_multiple_fields_message_succeeds() {
    // warn!(store: account.id = %id, block.number = n, "msg")  →  ok
    let result = warn2(quote! { store: account.id = %id, block.number = n, "msg" });
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn warn_component_nullifier_field_succeeds() {
    // warn!(rpc: nullifier.id = %id, "msg")  –  nullifier.id allowlisted  →  ok
    let result = warn2(quote! { rpc: nullifier.id = %id, "msg" });
    assert!(result.is_ok(), "{result:?}");
}

// ── returns_result false-positive regression ──────────────────────────────────

#[test]
fn instrument_report_on_fake_result_fn_fails() {
    // `NotAResult` contains "Result" as a substring → the string-contains check
    // would incorrectly accept this, but the typed check must reject it.
    let result = instrument2(quote! { rpc: report }, item_fake_result_fn());
    assert!(result.is_err(), "expected error: report requires Result return, got {result:?}");
}

#[test]
fn instrument_err_on_fake_result_fn_fails() {
    // Same false-positive gate for `err`.
    let result = instrument2(quote! { rpc: err }, item_fake_result_fn());
    assert!(result.is_err(), "expected error: err requires Result return, got {result:?}");
}

// ── per-level log dispatch regression ─────────────────────────────────────────

/// Checks that a log expansion contains the expected level identifier.
fn assert_level(result: syn::Result<TokenStream2>, expected_level: &str) {
    let ts = result.expect("expansion should succeed");
    let s = ts.to_string();
    assert!(
        s.contains(expected_level),
        "expected level `{expected_level}` in output, got: {s}"
    );
}

#[test]
fn error_level_dispatch() {
    assert_level(error2(quote! { "msg" }), "ERROR");
}

#[test]
fn warn_level_dispatch() {
    assert_level(warn2(quote! { "msg" }), "WARN");
}

#[test]
fn info_level_dispatch() {
    assert_level(info2(quote! { "msg" }), "INFO");
}

#[test]
fn debug_level_dispatch() {
    assert_level(debug2(quote! { "msg" }), "DEBUG");
}

#[test]
fn trace_level_dispatch() {
    assert_level(trace2(quote! { "msg" }), "TRACE");
}

// ── async fn support ─────────────────────────────────────────────────────────

/// `async fn` returning `Result` – `report` must succeed.
fn item_async_result_fn() -> TokenStream2 {
    quote! { async fn foo() -> Result<(), String> { Ok(()) } }
}

/// `async fn` returning nothing – `report` must fail.
fn item_async_bare_fn() -> TokenStream2 {
    quote! { async fn foo() {} }
}

#[test]
fn instrument_report_on_async_result_fn_succeeds() {
    // async fn returning Result is syntactically identical to a sync Result fn
    // from syn's perspective; the declared return type is Result, not a Future.
    let result = instrument2(quote! { rpc: report }, item_async_result_fn());
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn instrument_err_on_async_result_fn_succeeds() {
    let result = instrument2(quote! { rpc: err }, item_async_result_fn());
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn instrument_report_on_async_bare_fn_fails() {
    let result = instrument2(quote! { rpc: report }, item_async_bare_fn());
    assert!(result.is_err(), "{result:?}");
}

// ── impl Future / Box<dyn Future> rejection ───────────────────────────────────

/// `fn` returning `impl Future<Output = Result<…>>` – `report` must be rejected
/// with a clear error because the body-wrap codegen cannot `.await` the block.
fn item_impl_future_result_fn() -> TokenStream2 {
    quote! {
        fn foo() -> impl ::std::future::Future<Output = Result<(), String>> {
            async { Ok(()) }
        }
    }
}

/// `fn` returning `Pin<Box<dyn Future<Output = Result<…>>>>` – same restriction.
fn item_pin_box_future_result_fn() -> TokenStream2 {
    quote! {
        fn foo() -> ::std::pin::Pin<Box<dyn ::std::future::Future<Output = Result<(), String>>>> {
            Box::pin(async { Ok(()) })
        }
    }
}

#[test]
fn instrument_report_on_impl_future_fails() {
    let result = instrument2(quote! { rpc: report }, item_impl_future_result_fn());
    assert!(result.is_err(), "expected error for impl Future, got {result:?}");
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("impl Future"), "unexpected error message: {msg}");
}

#[test]
fn instrument_err_on_impl_future_fails() {
    let result = instrument2(quote! { rpc: err }, item_impl_future_result_fn());
    assert!(result.is_err(), "expected error for impl Future, got {result:?}");
}

#[test]
fn instrument_report_on_pin_box_future_fails() {
    let result = instrument2(quote! { rpc: report }, item_pin_box_future_result_fn());
    assert!(result.is_err(), "expected error for Box<dyn Future>, got {result:?}");
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("Box<dyn Future>"), "unexpected error message: {msg}");
}

#[test]
fn instrument_err_on_pin_box_future_fails() {
    let result = instrument2(quote! { rpc: err }, item_pin_box_future_result_fn());
    assert!(result.is_err(), "expected error for Box<dyn Future>, got {result:?}");
}
