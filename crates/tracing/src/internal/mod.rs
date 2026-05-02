//! Internal tracing plumbing.
//!
//! These modules are deliberately not public API. They route crate-owned operational signals, such
//! as panics and user-facing field bridges, through `tracing` without exposing raw plumbing events
//! as normal user-visible output.

mod active_span;
mod control_plane;
mod filters;
mod panic;
mod user_bridge;

pub(crate) use active_span::{ActiveSpanLayer, UserFacingActiveSpanLayer};
pub use active_span::{enter_current_span, track_current_span};
pub(crate) use control_plane::ControlPlaneEventLayer;
pub(crate) use filters::{
    OnlyControlPlaneEvents,
    with_control_plane_events,
    without_user_log_events,
};
pub(crate) use panic::emit_panic;
pub(crate) use user_bridge::record_user_field_bridge;

#[cfg(test)]
use self::active_span::active_span;
#[cfg(test)]
use self::active_span::enter_span;
#[cfg(test)]
pub(crate) use self::control_plane::CONTROL_PLANE_TARGET;
pub(crate) use self::control_plane::is_control_plane_target;
#[cfg(test)]
use self::control_plane::{
    ControlPlaneEventFields,
    SelectedSpanGuard,
    TRACING_PANIC_TARGET,
    u64_to_i64,
};
#[cfg(test)]
use self::filters::IgnoreControlPlaneEvents;
#[cfg(test)]
use self::panic::exportable_or_active_span;

#[cfg(test)]
mod tests {
    use std::future::{Future, pending};
    use std::pin::pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context as TaskContext, Poll, RawWaker, RawWakerVTable, Waker};

    use opentelemetry::Value;
    use opentelemetry::trace::Status;
    use opentelemetry_sdk::trace::SpanData;
    use tracing::field::{Field, Visit};
    use tracing::subscriber::with_default;
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::Context;
    use tracing_subscriber::prelude::*;

    use super::{
        ActiveSpanLayer,
        CONTROL_PLANE_TARGET,
        ControlPlaneEventFields,
        ControlPlaneEventLayer,
        IgnoreControlPlaneEvents,
        OnlyControlPlaneEvents,
        SelectedSpanGuard,
        TRACING_PANIC_TARGET,
        active_span,
        enter_span,
        exportable_or_active_span,
        track_current_span,
    };
    use crate::test_utils::{TestExporter, assert_attribute};

    #[test]
    fn control_plane_layer_records_panic_fields_on_current_span() {
        let spans = exported_spans_with_control_plane_layer(|| {
            let span = tracing::info_span!("panic_parent");
            let _guard = span.enter();
            let _selected_span = SelectedSpanGuard::new(span.clone());

            tracing::event!(
                target: TRACING_PANIC_TARGET,
                tracing::Level::ERROR,
                panic.payload = "test panic",
                panic.location = "src/lib.rs:42:7",
                "A panic occurred"
            );
        });
        let span = span_by_name(&spans, "panic_parent");

        assert_attribute(span, "panic.payload", "test panic");
        assert_attribute(span, "panic.location", "src/lib.rs:42:7");
        assert_eq!(span.status, Status::Error { description: "panic: test panic".into() });
        assert!(
            span.events.events.is_empty(),
            "raw control-plane events must not be exported: {:?}",
            span.events.events
        );
    }

    #[test]
    fn control_plane_layer_bridges_panic_status_to_tracing_error_field() {
        #[derive(Clone, Default)]
        struct ErrorRecordLayer {
            error: Arc<Mutex<Option<String>>>,
        }

        impl<S> Layer<S> for ErrorRecordLayer
        where
            S: tracing::Subscriber,
        {
            fn on_record(
                &self,
                _span: &tracing::span::Id,
                values: &tracing::span::Record<'_>,
                _ctx: Context<'_, S>,
            ) {
                let mut visitor = ErrorFieldVisitor::default();
                values.record(&mut visitor);
                if let Some(error) = visitor.error {
                    *self.error.lock().expect("error field lock poisoned") = Some(error);
                }
            }
        }

        #[derive(Default)]
        struct ErrorFieldVisitor {
            error: Option<String>,
        }

        impl Visit for ErrorFieldVisitor {
            fn record_str(&mut self, field: &Field, value: &str) {
                if field.name() == "miden.error" {
                    self.error = Some(value.to_owned());
                }
            }

            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                if field.name() == "miden.error" {
                    self.error = Some(format!("{value:?}").trim_matches('"').to_owned());
                }
            }
        }

        let error_layer = ErrorRecordLayer::default();
        let captured = error_layer.error.clone();
        let subscriber = tracing_subscriber::registry()
            .with(ControlPlaneEventLayer.with_filter(OnlyControlPlaneEvents))
            .with(error_layer);

        with_default(subscriber, || {
            let span = tracing::info_span!(
                target: "rpc",
                "panic_parent",
                miden.error = tracing::field::Empty
            );
            let _guard = span.enter();
            let _selected_span = SelectedSpanGuard::new(span.clone());

            tracing::event!(
                target: TRACING_PANIC_TARGET,
                tracing::Level::ERROR,
                panic.payload = "panic visible to stdout",
                "A panic occurred"
            );
        });

        assert_eq!(
            captured.lock().expect("error field lock poisoned").as_deref(),
            Some("panic: panic visible to stdout")
        );
    }

    #[test]
    fn control_plane_event_filter_rejects_tracing_panic_events() {
        let spans = exported_spans_with_control_plane_layer(|| {
            let span = tracing::error_span!(target: CONTROL_PLANE_TARGET, "spanless_panic");
            let _guard = span.enter();
            let _selected_span = SelectedSpanGuard::new(span.clone());
            tracing::event!(
                target: TRACING_PANIC_TARGET,
                tracing::Level::ERROR,
                panic.payload = Some("test panic"),
                "A panic occurred"
            );
        });
        let span = span_by_name(&spans, "spanless_panic");

        assert_attribute(span, "panic.payload", "test panic");
        assert_eq!(span.status, Status::Error { description: "panic: test panic".into() });
        assert!(span.events.events.is_empty());
    }

    #[test]
    fn control_plane_layer_records_panic_on_active_parent_when_child_span_is_disabled() {
        let spans = exported_spans_with_filter("info", || {
            let root = tracing::info_span!(target: "rpc", "panic_root");
            let _root_guard = root.enter();
            let _active_root = enter_span(&root);

            let disabled_child = tracing::debug_span!(target: "rpc", "disabled_child");
            let _disabled_guard = disabled_child.enter();
            let selected = active_span().unwrap_or_else(tracing::Span::current);
            let _selected_span = SelectedSpanGuard::new(selected);

            tracing::event!(
                target: TRACING_PANIC_TARGET,
                tracing::Level::ERROR,
                panic.payload = "panic in disabled child",
                "A panic occurred"
            );
        });
        let span = span_by_name(&spans, "panic_root");

        assert_attribute(span, "panic.payload", "panic in disabled child");
        assert_eq!(
            span.status,
            Status::Error {
                description: "panic: panic in disabled child".into(),
            }
        );
        assert!(spans.iter().all(|span| span.name != "disabled_child"));
        assert!(spans.iter().all(|span| span.name != "spanless_panic"));
    }

    #[test]
    fn active_span_future_tracks_span_only_during_poll() {
        let root = tracing::info_span!(target: "rpc", "async_panic_root");
        let future = {
            let _guard = root.enter();
            track_current_span(pending::<()>())
        };

        assert!(active_span().is_none());

        let mut future = pin!(future);
        let waker = noop_waker();
        let mut cx = TaskContext::from_waker(&waker);
        assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
        assert!(active_span().is_none());
    }

    #[test]
    fn active_span_layer_tracks_public_entered_span() {
        let subscriber = tracing_subscriber::registry().with(ActiveSpanLayer);

        with_default(subscriber, || {
            let root = tracing::info_span!(target: "rpc", "layer_tracked_root");
            let expected_id = root.id();

            {
                let _guard = root.enter();
                let active_id = active_span().and_then(|span| span.id());
                assert_eq!(active_id, expected_id);
            }

            assert!(active_span().is_none());
        });
    }

    #[test]
    fn explicit_active_span_guard_does_not_pop_layer_tracked_span() {
        let subscriber = tracing_subscriber::registry().with(ActiveSpanLayer);

        with_default(subscriber, || {
            let root = tracing::info_span!(target: "rpc", "layer_and_macro_tracked_root");
            let expected_id = root.id();
            let _span_guard = root.enter();

            {
                let _macro_guard = enter_span(&root);
            }

            let active_id = active_span().and_then(|span| span.id());
            assert_eq!(active_id, expected_id);
        });

        assert!(active_span().is_none());
    }

    #[test]
    fn active_span_selection_ignores_third_party_current_span() {
        let subscriber = tracing_subscriber::registry().with(ActiveSpanLayer);

        with_default(subscriber, || {
            let third_party = tracing::info_span!(target: "tokio::runtime", "third_party_root");
            let _third_party_guard = third_party.enter();

            assert!(active_span().is_none());
            assert!(exportable_or_active_span(&tracing::Span::current()).is_none());
        });

        let subscriber = tracing_subscriber::registry().with(ActiveSpanLayer);

        with_default(subscriber, || {
            let root = tracing::info_span!(target: "rpc", "exported_root");
            let expected_id = root.id();
            let _root_guard = root.enter();

            let third_party = tracing::info_span!(target: "tokio::runtime", "third_party_child");
            let _third_party_guard = third_party.enter();

            let active_id = active_span().and_then(|span| span.id());
            let selected_id =
                exportable_or_active_span(&tracing::Span::current()).and_then(|span| span.id());
            assert_eq!(active_id, expected_id);
            assert_eq!(selected_id, expected_id);
        });
    }

    #[test]
    fn active_span_layer_keeps_outer_enter_active_when_same_span_is_reentered() {
        let subscriber = tracing_subscriber::registry().with(ActiveSpanLayer);

        with_default(subscriber, || {
            let root = tracing::info_span!(target: "rpc", "nested_layer_tracked_root");
            let expected_id = root.id();
            let outer = root.enter();

            {
                let _inner = root.enter();
                let active_id = active_span().and_then(|span| span.id());
                assert_eq!(active_id, expected_id);
            }

            let active_id = active_span().and_then(|span| span.id());
            assert_eq!(active_id, expected_id);

            drop(outer);
            assert!(active_span().is_none());
        });
    }

    fn exported_spans_with_control_plane_layer(record: impl FnOnce()) -> Vec<SpanData> {
        exported_spans_with_filter("trace", record)
    }

    fn exported_spans_with_filter(filter: &str, record: impl FnOnce()) -> Vec<SpanData> {
        let exporter = TestExporter::default();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let tracer = opentelemetry::trace::TracerProvider::tracer(
            &provider,
            "miden-node-tracing-control-plane-test",
        );
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(filter))
            .with(ActiveSpanLayer)
            .with(ControlPlaneEventLayer.with_filter(OnlyControlPlaneEvents))
            .with(
                tracing_opentelemetry::layer()
                    .with_tracer(tracer)
                    .with_filter(IgnoreControlPlaneEvents),
            );

        with_default(subscriber, record);

        drop(provider);
        let spans = exporter.0.lock().expect("span exporter lock poisoned");
        spans.clone()
    }

    fn span_by_name<'a>(spans: &'a [SpanData], name: &str) -> &'a SpanData {
        spans
            .iter()
            .find(|span| span.name == name)
            .unwrap_or_else(|| panic!("missing span {name}; spans: {spans:?}"))
    }

    fn noop_waker() -> Waker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            noop_raw_waker()
        }
        unsafe fn wake(_: *const ()) {}
        unsafe fn wake_by_ref(_: *const ()) {}
        unsafe fn drop(_: *const ()) {}

        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);

        fn noop_raw_waker() -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }

        // SAFETY: the vtable functions do not dereference the null data pointer.
        unsafe { Waker::from_raw(noop_raw_waker()) }
    }

    #[test]
    fn u64_values_saturate_when_recorded_as_i64() {
        let mut fields = ControlPlaneEventFields::default();
        fields.record_panic_attribute("panic.value", Value::I64(super::u64_to_i64(u64::MAX)));

        assert_eq!(fields.panic_attributes[0].1, Value::I64(i64::MAX));
    }
}
