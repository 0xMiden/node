use std::error::Error;

/// Converts errors to typed tracing values through method resolution.
///
/// Method resolution dereferences error wrappers such as `anyhow::Error` and `Box<dyn Error>`.
pub trait AsDynError {
    fn as_dyn_error(&self) -> &(dyn Error + 'static);
}

impl<E: Error + 'static> AsDynError for E {
    fn as_dyn_error(&self) -> &(dyn Error + 'static) {
        self
    }
}

impl AsDynError for dyn Error + 'static {
    fn as_dyn_error(&self) -> &(dyn Error + 'static) {
        self
    }
}

impl AsDynError for dyn Error + Send + 'static {
    fn as_dyn_error(&self) -> &(dyn Error + 'static) {
        self
    }
}

impl AsDynError for dyn Error + Sync + 'static {
    fn as_dyn_error(&self) -> &(dyn Error + 'static) {
        self
    }
}

impl AsDynError for dyn Error + Send + Sync + 'static {
    fn as_dyn_error(&self) -> &(dyn Error + 'static) {
        self
    }
}

impl AsDynError for dyn crate::ErrorReport + Send + Sync + 'static {
    fn as_dyn_error(&self) -> &(dyn Error + 'static) {
        self
    }
}
