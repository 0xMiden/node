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

/// Static metadata about an event declared through the Miden tracing macros.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventMetadata {
    /// The tracing target used by the event.
    pub target: &'static str,
    /// The level used by the event.
    pub level: SpanLevel,
    /// The static event message format string.
    pub message: &'static str,
    /// Whether this event should be surfaced in user-facing logs.
    pub user: bool,
}

/// Static metadata about telemetry declared through the Miden tracing macros.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TelemetryMetadata {
    /// A span declaration.
    Span(SpanMetadata),
    /// An event declaration.
    Event(EventMetadata),
}

impl TelemetryMetadata {
    /// Returns whether this telemetry should be surfaced in user-facing logs.
    pub const fn user(&self) -> bool {
        match self {
            Self::Span(span) => span.user,
            Self::Event(event) => event.user,
        }
    }

    /// Returns the span metadata when this item describes a span.
    pub const fn as_span(&self) -> Option<&SpanMetadata> {
        match self {
            Self::Span(span) => Some(span),
            Self::Event(_) => None,
        }
    }

    /// Returns the event metadata when this item describes an event.
    pub const fn as_event(&self) -> Option<&EventMetadata> {
        match self {
            Self::Span(_) => None,
            Self::Event(event) => Some(event),
        }
    }
}

/// The level used by telemetry declared through the Miden tracing macros.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SpanLevel {
    /// Trace-level telemetry.
    Trace,
    /// Debug-level telemetry.
    Debug,
    /// Info-level telemetry.
    Info,
    /// Warn-level telemetry.
    Warn,
    /// Error-level telemetry.
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

inventory::collect!(TelemetryMetadata);

/// Returns metadata for all spans and events declared through the Miden tracing macros.
pub fn registered_metadata() -> impl Iterator<Item = &'static TelemetryMetadata> {
    inventory::iter::<TelemetryMetadata>.into_iter()
}

/// Returns metadata for all spans declared through the Miden tracing macros in this binary.
pub fn registered_spans() -> impl Iterator<Item = &'static SpanMetadata> {
    registered_metadata().filter_map(TelemetryMetadata::as_span)
}

/// Returns metadata for all events declared through the Miden tracing macros in this binary.
pub fn registered_events() -> impl Iterator<Item = &'static EventMetadata> {
    registered_metadata().filter_map(TelemetryMetadata::as_event)
}

/// Returns metadata for spans and events marked for user-facing logs.
pub fn registered_user_facing_metadata() -> impl Iterator<Item = &'static TelemetryMetadata> {
    registered_metadata().filter(|metadata| metadata.user())
}
