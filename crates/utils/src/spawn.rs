use tokio::task::JoinHandle;
use tracing::Span;

/// Spawn a blocking task in the current tracing span.
pub fn spawn_blocking_in_current_span<F, R>(f: F) -> JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    spawn_blocking_in_span(f, Span::current())
}

/// Spawn a blocking task in a span.
pub fn spawn_blocking_in_span<F, R>(f: F, span: Span) -> JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    #[expect(clippy::disallowed_methods)]
    tokio::task::spawn_blocking(move || span.in_scope(f))
}
