use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::Registry;
use tracing_subscriber::registry::LookupSpan as _;

/// How a failed operation is reported in telemetry, with a short name for what happened.
///
/// The class is exported on the failed span as `failure.class` and the kind as `failure.kind`.
/// Only a rejection leaves the span status unset: rejecting a bad request is the node behaving
/// correctly, so alerts on failed spans see node failures only. Every span that is marked failed
/// records a transient or fault class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// The node rejected a request because of the request itself or the state it refers to, such as
    /// an invalid proof or an expired transaction.
    Rejected(&'static str),
    /// A node failure that is expected to resolve itself, such as a dependency that is briefly
    /// unavailable. It matters only when it persists.
    Transient(&'static str),
    /// A node failure that needs an operator, such as a database error or a bug.
    Fault(&'static str),
}

impl FailureClass {
    /// The class name exported as `failure.class`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Rejected(_) => "rejected",
            Self::Transient(_) => "transient",
            Self::Fault(_) => "fault",
        }
    }

    /// The short name for what happened, exported as `failure.kind`.
    pub fn kind(self) -> &'static str {
        match self {
            Self::Rejected(kind) | Self::Transient(kind) | Self::Fault(kind) => kind,
        }
    }

    /// Returns the same class with a different kind.
    #[must_use]
    pub fn with_kind(self, kind: &'static str) -> Self {
        match self {
            Self::Rejected(_) => Self::Rejected(kind),
            Self::Transient(_) => Self::Transient(kind),
            Self::Fault(_) => Self::Fault(kind),
        }
    }

    /// Returns true if the request was rejected rather than failed in the node.
    pub fn is_rejection(self) -> bool {
        matches!(self, Self::Rejected(_))
    }

    /// Classifies a gRPC status code returned by a server, with the code's name as the kind.
    ///
    /// Codes that describe the request, such as `INVALID_ARGUMENT` or `FAILED_PRECONDITION`, are
    /// rejections. `RESOURCE_EXHAUSTED` is also a rejection: rate limiting and a full mempool are
    /// the node protecting itself, and the status code keeps them queryable. `CANCELLED`,
    /// `DEADLINE_EXCEEDED` and `UNAVAILABLE` are transient. `UNKNOWN`, `UNIMPLEMENTED`, `INTERNAL`
    /// and `DATA_LOSS` are faults, as is an `OK` status returned as an error.
    ///
    /// `CANCELLED` is transient rather than a rejection because the server's request timeout also
    /// reports it.
    pub fn from_grpc_code(code: tonic::Code) -> Self {
        use tonic::Code;

        let kind = grpc_code_name(code);
        match code {
            Code::InvalidArgument
            | Code::NotFound
            | Code::AlreadyExists
            | Code::PermissionDenied
            | Code::ResourceExhausted
            | Code::FailedPrecondition
            | Code::Aborted
            | Code::OutOfRange
            | Code::Unauthenticated => Self::Rejected(kind),
            Code::Cancelled | Code::DeadlineExceeded | Code::Unavailable => Self::Transient(kind),
            Code::Ok | Code::Unknown | Code::Unimplemented | Code::Internal | Code::DataLoss => {
                Self::Fault(kind)
            },
        }
    }

    /// The class of a failure that is logged at `ERROR`, and so marks its span as failed.
    ///
    /// An unclassified error is a fault of kind `unclassified`. A rejection logged at `ERROR` is
    /// a fault of the same kind, because the span is marked failed regardless.
    pub fn of_failed_span(class: Option<Self>) -> Self {
        match class {
            Some(Self::Rejected(kind)) => Self::Fault(kind),
            Some(class) => class,
            None => Self::Fault(UNCLASSIFIED),
        }
    }

    /// The class of a failure reported by a component the node calls.
    ///
    /// A rejection becomes a fault: when the node's own request is rejected, such as a block the
    /// validator refuses to sign, the node sent a bad request. Other classes are unchanged.
    pub fn from_dependency(class: Self) -> Self {
        match class {
            Self::Rejected(kind) => Self::Fault(kind),
            class => class,
        }
    }

    /// Records the class and kind as attributes of `span`, unless the span already records a
    /// failure.
    ///
    /// The first failure recorded on a span wins. Several mechanisms can report the same failure,
    /// such as an error event inside a function that then returns the error, and the first one is
    /// also the one that set the span status.
    ///
    /// This does not change the span status.
    pub fn record(self, span: &tracing::Span) {
        if mark_failure_recorded(span) {
            span.set_attribute("failure.class", self.name());
            span.set_attribute("failure.kind", self.kind());
        }
    }
}

/// The failure kind of an error that does not implement [`Classified`].
const UNCLASSIFIED: &str = "unclassified";

/// Marks `span` as recording a failure. Returns false if it already did.
///
/// The mark is kept in the span's registry extensions. Without a registry, every call returns
/// true.
fn mark_failure_recorded(span: &tracing::Span) -> bool {
    struct FailureRecorded;

    let mut first = true;
    span.with_subscriber(|(id, dispatch)| {
        if let Some(span) = dispatch.downcast_ref::<Registry>().and_then(|r| r.span(id)) {
            let mut extensions = span.extensions_mut();
            first = extensions.get_mut::<FailureRecorded>().is_none();
            if first {
                extensions.insert(FailureRecorded);
            }
        }
    });
    first
}

/// Records the failure of an error returned from a function instrumented with
/// `#[miden_instrument(err)]`, whose error event is logged at `level`. Returns true if the error
/// is a rejection.
///
/// A rejection is always recorded. Other failures are recorded only when logged at `ERROR`,
/// since only then is the span marked failed.
#[doc(hidden)]
pub fn record_returned_failure(class: Option<FailureClass>, level: tracing::Level) -> bool {
    let span = tracing::Span::current();
    match class {
        Some(class) if class.is_rejection() => {
            class.record(&span);
            true
        },
        class => {
            if level == tracing::Level::ERROR {
                FailureClass::of_failed_span(class).record(&span);
            }
            false
        },
    }
}

/// Records the failure of an error logged with the `error!` macro on the current span, which the
/// `ERROR` event marks as failed.
#[doc(hidden)]
pub fn record_logged_failure(class: Option<FailureClass>) {
    FailureClass::of_failed_span(class).record(&tracing::Span::current());
}

/// An error that knows how its failure is reported in telemetry.
///
/// `#[miden_instrument(err)]` uses this to choose the error event's level and the span's failure
/// attributes. Errors without an implementation are reported as faults of kind `unclassified`.
pub trait Classified {
    /// The error's failure class and kind.
    fn failure_class(&self) -> FailureClass;
}

impl Classified for tonic::Status {
    fn failure_class(&self) -> FailureClass {
        FailureClass::from_grpc_code(self.code())
    }
}

/// The gRPC status code name in snake case, such as `invalid_argument`.
fn grpc_code_name(code: tonic::Code) -> &'static str {
    use tonic::Code;

    match code {
        Code::Ok => "ok",
        Code::Cancelled => "cancelled",
        Code::Unknown => "unknown",
        Code::InvalidArgument => "invalid_argument",
        Code::DeadlineExceeded => "deadline_exceeded",
        Code::NotFound => "not_found",
        Code::AlreadyExists => "already_exists",
        Code::PermissionDenied => "permission_denied",
        Code::ResourceExhausted => "resource_exhausted",
        Code::FailedPrecondition => "failed_precondition",
        Code::Aborted => "aborted",
        Code::OutOfRange => "out_of_range",
        Code::Unimplemented => "unimplemented",
        Code::Internal => "internal",
        Code::Unavailable => "unavailable",
        Code::DataLoss => "data_loss",
        Code::Unauthenticated => "unauthenticated",
    }
}

/// Selects an error's failure class through method resolution.
///
/// Errors that implement [`Classified`] resolve to [`ClassifiedFailure`] when called on `&E`.
/// Other errors fall back to [`UnclassifiedFailure`], which is implemented on `&&E` and is only
/// reached through auto-referencing.
pub trait ClassifiedFailure {
    fn miden_failure_class(&self) -> Option<FailureClass>;
}

impl<E: Classified + ?Sized> ClassifiedFailure for E {
    fn miden_failure_class(&self) -> Option<FailureClass> {
        Some(self.failure_class())
    }
}

/// The fallback for errors that do not implement [`Classified`]. See [`ClassifiedFailure`].
pub trait UnclassifiedFailure {
    fn miden_failure_class(&self) -> Option<FailureClass>;
}

impl<E: ?Sized> UnclassifiedFailure for &E {
    fn miden_failure_class(&self) -> Option<FailureClass> {
        None
    }
}
