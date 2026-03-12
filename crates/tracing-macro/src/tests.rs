use proc_macro2::TokenStream as TokenStream2;
use quote::quote;

use crate::instrument::instrument2;

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
