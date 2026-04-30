use std::fmt;

/// Static metadata about a span declared through the Miden tracing macros.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SpanMetadata {
    /// The tracing target used by the span.
    pub target: &'static str,
    /// The level used by the span.
    pub level: SpanLevel,
    /// The span name.
    pub name: &'static str,
    /// A human-oriented description of what the span covers.
    pub description: Option<&'static str>,
    /// Whether this span should be surfaced in user-facing logs.
    pub user: bool,
}

/// The level used by a span declared through the Miden tracing macros.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SpanLevel {
    /// Trace-level span.
    Trace,
    /// Debug-level span.
    Debug,
    /// Info-level span.
    Info,
    /// Warn-level span.
    Warn,
    /// Error-level span.
    Error,
}

impl SpanLevel {
    /// Returns the lowercase textual representation used by tracing filters.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    /// Returns the corresponding [`tracing::Level`].
    pub const fn as_tracing_level(self) -> tracing::Level {
        match self {
            Self::Trace => tracing::Level::TRACE,
            Self::Debug => tracing::Level::DEBUG,
            Self::Info => tracing::Level::INFO,
            Self::Warn => tracing::Level::WARN,
            Self::Error => tracing::Level::ERROR,
        }
    }
}

impl fmt::Display for SpanLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<SpanLevel> for tracing::Level {
    fn from(level: SpanLevel) -> Self {
        level.as_tracing_level()
    }
}

inventory::collect!(SpanMetadata);

/// Returns metadata for all spans declared through the Miden tracing macros in this binary.
pub fn registered_spans() -> impl Iterator<Item = &'static SpanMetadata> {
    inventory::iter::<SpanMetadata>.into_iter()
}
