use std::panic::PanicHookInfo;

/// Emits the panic control-plane event.
///
/// `ControlPlaneEventLayer` attaches the resulting `tracing-panic` event to the nearest
/// exportable span in the event scope, or creates a fallback span when no such scope exists.
pub(crate) fn emit_panic(info: &PanicHookInfo<'_>) {
    tracing_panic::panic_hook(info);
}
