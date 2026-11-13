use std::sync::{Arc, Mutex};
use std::time::Duration;

use miden_node_tracing::warn;
use miden_node_utils::formatting::format_endpoint;
use tonic::Status;
use tonic::transport::{Channel, Endpoint};

/// Shares a connection across clients and replaces it when a request times out.
///
/// A hung connection can repeatedly time out without being closed, leaving retries unable to make
/// progress. Our policy is to replace the connection after a timeout so future calls can recover.
/// Tonic's timeout only covers the initial wait for response headers, so reading the response body
/// can still hang indefinitely. This helper applies the timeout to the complete unary call,
/// including its body and trailers. Subscriptions are timed only until they start, since they can
/// legitimately stay open indefinitely.
#[derive(Clone, Debug)]
pub struct RecoveringChannel(Arc<Shared>);

#[derive(Debug)]
struct Shared {
    endpoint: Endpoint,
    current: Mutex<Option<Arc<Channel>>>,
    label: String,
}

impl RecoveringChannel {
    /// Shares connection selection and retirement across client clones.
    pub fn new(endpoint: Endpoint, channel: Channel) -> Self {
        Self(Arc::new(Shared {
            label: url::Url::parse(&endpoint.uri().to_string())
                .map_or_else(|_| "gRPC endpoint".to_owned(), |url| format_endpoint(&url)),
            endpoint,
            current: Mutex::new(Some(Arc::new(channel))),
        }))
    }

    /// Runs one client method within its complete budget and retires its connection on expiry.
    ///
    /// The caller supplies tonic's complete unary future, or its stream establishment future.
    /// Endpoint timeouts stop at headers and PINGs prove transport liveness rather than RPC progress,
    /// so this deadline must surround the method. Cancellation and application errors preserve the
    /// connection; no request is replayed here.
    pub async fn call<T, F>(
        &self,
        timeout: Duration,
        call: impl FnOnce(Channel) -> F,
    ) -> Result<T, Status>
    where
        F: Future<Output = Result<T, Status>>,
    {
        assert!(!timeout.is_zero(), "gRPC deadline must be positive");
        let deadline = tokio::time::Instant::now() + timeout;
        // The lock selects a connection without waiting for readiness or network I/O.
        let channel = self
            .0
            .current
            .lock()
            .expect("gRPC channel lock poisoned")
            .get_or_insert_with(|| Arc::new(self.0.endpoint.connect_lazy()))
            .clone();
        // Box the RPC future so callers do not inherit tonic's large, deeply nested future layout.
        let response = Box::pin(call((*channel).clone()));
        if let Ok(result) = tokio::time::timeout_at(deadline, response).await {
            result
        } else {
            self.0.retire(&channel);
            Err(Status::deadline_exceeded("gRPC response deadline expired"))
        }
    }
}

impl Shared {
    /// Retires the timed-out channel for future calls across all clones, without replaying requests.
    ///
    /// The identity check prevents a late timeout from retiring a replacement channel. Existing
    /// calls may finish on the old connection; ordinary cancellation does not retire it. Replaying
    /// a timed-out request here would be unsafe because the server may already have performed it.
    fn retire(&self, channel: &Arc<Channel>) {
        let mut current = self.current.lock().expect("gRPC channel lock poisoned");
        if current.as_ref().is_some_and(|current| Arc::ptr_eq(current, channel)) {
            *current = None;
            drop(current);
            warn!(
                "Retiring gRPC channel after deadline expiry",
                dependency.endpoint = self.label.as_str(),
                reason = "deadline expired"
            );
        }
    }
}
