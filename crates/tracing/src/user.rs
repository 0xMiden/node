// Keep the macro argument transport-agnostic. `user` means "safe to show to an operator"; the
// concrete exporter decides whether that becomes stdout, a UI notification, or something else.
pub(crate) const ATTRIBUTE_KEY: &str = "miden.user";
