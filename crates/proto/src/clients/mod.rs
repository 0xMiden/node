//! gRPC client builder utilities for Miden node.
//!
//! This module provides a unified type-safe [`Builder`] for creating various gRPC clients with
//! explicit configuration decisions for TLS and metadata, with configurable default timeouts.
//!
//! Unary deadlines cover channel readiness, response headers, the body, and trailers. Server
//! streams use the deadline only for establishment. Expiry retires the shared channel for future
//! calls without replaying requests or cancelling other calls. HTTP/2 keepalives detect transport
//! failures but cannot establish that a server application is making progress.
//!
//! # Examples
//!
//! ```rust
//! # use miden_node_proto::clients::{Builder, WantsTls, RpcClient};
//! # use url::Url;
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Create an RPC client with OTEL and TLS
//! let url = Url::parse("https://example.com:8080")?;
//! let client: RpcClient = Builder::new(url)
//!     .with_tls()?                   // or `.without_tls()`
//!     .without_metadata_version()    // or `.with_metadata_version("1.0".into())`
//!     .without_metadata_genesis()    // or `.with_metadata_genesis(genesis)`
//!     .without_auth_header()         // or `.with_auth_header_value(AsciiMetadataValue::from_static("value"))`
//!     .with_otel_context_injection() // or `.without_otel_context_injection()`
//!     .connect::<RpcClient>()
//!     .await?;
//! # Ok(())
//! # }
//! ```

use std::marker::PhantomData;
use std::str::FromStr;
use std::time::Duration;

use http::header::ACCEPT;
use miden_node_tracing::grpc::OtelInterceptor;
use miden_node_tracing::{debug, info, warn};
use miden_node_utils::grpc::DEFAULT_MAX_DECODING_MESSAGE_SIZE;
use miden_node_utils::retry::RetryableGrpc;
use miden_protocol::Word;
use miden_protocol::batch::ProposedBatch;
use tonic::metadata::AsciiMetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Error as TransportError};
use tonic::{Request, Status};
use url::Url;

use crate::generated;

/// Default deadline for complete unary responses and subscription establishment.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

mod channel;
pub use channel::RecoveringChannel;

mod foreign_account;
mod usdcx_faucet;

pub use foreign_account::ForeignAccount;
pub use usdcx_faucet::UsdcxFaucet;

#[derive(Clone)]
pub struct Interceptor {
    otel: Option<OtelInterceptor>,
    accept: AsciiMetadataValue,
    auth_header_value: Option<AsciiMetadataValue>,
}

impl Default for Interceptor {
    fn default() -> Self {
        Self {
            otel: None,
            accept: AsciiMetadataValue::from_static(Self::MEDIA_TYPE),
            auth_header_value: None,
        }
    }
}

impl Interceptor {
    const MEDIA_TYPE: &str = "application/vnd.miden";
    const VERSION: &str = "version";
    const GENESIS: &str = "genesis";
    const NETWORK_TX_AUTH_HEADER_NAME: &str = "x-miden-network-tx-auth";

    fn new(
        enable_otel: bool,
        version: Option<&str>,
        genesis: Option<&str>,
        auth_header: Option<AsciiMetadataValue>,
    ) -> Self {
        if let Some(version) = version
            && !version.is_ascii()
        {
            panic!("version contains non-ascii values: {version}");
        }

        if let Some(genesis) = genesis
            && !genesis.is_ascii()
        {
            panic!("genesis contains non-ascii values: {genesis}");
        }

        let accept = match (version, genesis) {
            (None, None) => Self::MEDIA_TYPE.to_string(),
            (None, Some(genesis)) => format!("{}; {}={genesis}", Self::MEDIA_TYPE, Self::GENESIS),
            (Some(version), None) => format!("{}; {}={version}", Self::MEDIA_TYPE, Self::VERSION),
            (Some(version), Some(genesis)) => format!(
                "{}; {}={version}; {}={genesis}",
                Self::MEDIA_TYPE,
                Self::VERSION,
                Self::GENESIS
            ),
        };
        Self {
            otel: enable_otel.then_some(OtelInterceptor),
            // SAFETY: we checked that all values are ascii at the top of the function.
            accept: AsciiMetadataValue::from_str(&accept).unwrap(),
            auth_header_value: auth_header,
        }
    }
}

impl tonic::service::Interceptor for Interceptor {
    fn call(&mut self, mut request: tonic::Request<()>) -> Result<Request<()>, Status> {
        if let Some(mut otel) = self.otel {
            request = otel.call(request)?;
        }

        if request.metadata().get(ACCEPT.as_str()).is_none() {
            request.metadata_mut().insert(ACCEPT.as_str(), self.accept.clone());
        }

        if let Some(value) = &self.auth_header_value {
            request.metadata_mut().insert(Self::NETWORK_TX_AUTH_HEADER_NAME, value.clone());
        }

        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    mod message_size;
    mod recovery;
    mod tracing_targets;
    use super::*;

    #[test]
    fn interceptor_preserves_existing_accept_metadata() {
        let original_accept =
            AsciiMetadataValue::from_static("application/vnd.miden; version=1.2; genesis=0x1234");
        let mut request = Request::new(());
        request.metadata_mut().insert(ACCEPT.as_str(), original_accept.clone());

        let mut interceptor = Interceptor::new(false, Some("9.9"), Some("0xabcd"), None);
        let request = tonic::service::Interceptor::call(&mut interceptor, request)
            .expect("interceptor should succeed");

        assert_eq!(request.metadata().get(ACCEPT.as_str()), Some(&original_accept));
    }

    #[test]
    fn interceptor_inserts_accept_metadata_when_missing() {
        let mut interceptor = Interceptor::new(false, Some("9.9"), Some("0xabcd"), None);

        let request = tonic::service::Interceptor::call(&mut interceptor, Request::new(()))
            .expect("interceptor should succeed");

        assert_eq!(
            request.metadata().get(ACCEPT.as_str()).and_then(|value| value.to_str().ok()),
            Some("application/vnd.miden; version=9.9; genesis=0xabcd"),
        );
    }

    #[tokio::test]
    async fn connection_monitor_stops_when_cancelled() {
        let builder = Builder::new(Url::parse("http://127.0.0.1:1").unwrap())
            .without_tls()
            .without_metadata_version()
            .without_metadata_genesis()
            .without_auth_header()
            .without_otel_context_injection();
        let shutdown = miden_node_utils::shutdown::CancellationToken::new();
        shutdown.cancel();

        tokio::time::timeout(
            Duration::from_millis(100),
            builder.monitor::<RpcClient>("test-dependency", shutdown),
        )
        .await
        .expect("cancelled monitor should return promptly");
    }
}

// TYPE ALIASES TO AID LEGIBILITY
// ================================================================================================

type InterceptedChannel = InterceptedService<Channel, Interceptor>;
type GeneratedProvenTransaction = generated::submission::ProvenTransactionSubmission;
type SealedTransactionInputs = generated::submission::SealedTransactionInputs;

/// Per-clone request configuration sharing one recoverable connection with other clones.
#[derive(Clone)]
struct ClientConfig {
    channel: RecoveringChannel,
    interceptor: Interceptor,
    timeout: Duration,
    max_decoding_message_size: usize,
}

impl ClientConfig {
    fn new(channel: RecoveringChannel, interceptor: Interceptor) -> Self {
        Self {
            channel,
            interceptor,
            timeout: DEFAULT_REQUEST_TIMEOUT,
            max_decoding_message_size: DEFAULT_MAX_DECODING_MESSAGE_SIZE,
        }
    }

    async fn call<T, F>(
        &self,
        call: impl FnOnce(InterceptedChannel, usize) -> F,
    ) -> Result<T, Status>
    where
        F: Future<Output = Result<T, Status>>,
    {
        self.channel
            .call(self.timeout, |channel| {
                call(
                    InterceptedService::new(channel, self.interceptor.clone()),
                    self.max_decoding_message_size,
                )
            })
            .await
    }
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("channel", &self.channel)
            .field("timeout", &self.timeout)
            .field("max_decoding_message_size", &self.max_decoding_message_size)
            .finish_non_exhaustive()
    }
}

/// Trait for building gRPC clients from a common [`Builder`] configuration.
pub trait GrpcClient {
    fn with_interceptor(channel: RecoveringChannel, interceptor: Interceptor) -> Self;

    /// Sets this client's deadline for unary responses and subscription establishment.
    ///
    /// Other clones retain their budgets and transport settings; connection recovery remains
    /// shared. Clone the client before overriding the timeout for an individual call.
    /// An outer timeout only cancels the call and does not trigger connection recovery.
    #[must_use]
    fn with_timeout(self, timeout: Duration) -> Self;

    /// Sets the maximum encoded size of a received response or stream item.
    #[must_use]
    fn max_decoding_message_size(self, limit: usize) -> Self;
}

// The descriptor generator emits typed method declarations for this macro. Keeping the forwarding
// logic in Rust makes the deadline boundary auditable without embedding method bodies in strings.
macro_rules! grpc_client {
    ($name:ident, $raw:ty, { $( $(#[$doc:meta])* fn $method:ident($request:ty) -> $response:ty; )* }) => {
        #[derive(Clone, Debug)]
        pub struct $name($crate::clients::ClientConfig);

        impl $crate::clients::GrpcClient for $name {
            fn with_interceptor(channel: $crate::clients::RecoveringChannel, interceptor: $crate::clients::Interceptor) -> Self {
                Self($crate::clients::ClientConfig::new(channel, interceptor))
            }
            fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
                assert!(!timeout.is_zero(), "gRPC deadline must be positive");
                self.0.timeout = timeout;
                self
            }
            fn max_decoding_message_size(mut self, limit: usize) -> Self {
                self.0.max_decoding_message_size = limit;
                self
            }
        }

        impl $name {
            $(
                $(#[$doc])*
                pub async fn $method(&mut self, request: impl tonic::IntoRequest<$request>)
                    -> Result<tonic::Response<$response>, tonic::Status> {
                    let request = request.into_request();
                    self.0.call(|channel, limit| async move {
                        <$raw>::new(channel).max_decoding_message_size(limit).$method(request).await
                    }).await
                }
            )*
        }
    };
}

/// Client facades derived from the protobuf services.
///
/// Unary calls include body decoding and trailers in their deadline. Streaming calls bound
/// establishment only. Raw tonic clients are kept behind these facades to preserve that policy.
pub mod services {
    include!(concat!(env!("OUT_DIR"), "/client_facades/mod.rs"));
}

pub use services::miden_node_v1_node_service::NodeServiceClient as RpcClient;
pub use services::miden_note_transport_v1_note_transport_service::NoteTransportServiceClient as NoteTransportClient;
pub use services::miden_ntx_builder_v1_network_transaction_builder_service::NetworkTransactionBuilderServiceClient as NtxBuilderClient;
pub use services::miden_remote_prover_v1_prover_service::ProverServiceClient as RemoteProverClient;
pub use services::miden_remote_prover_v1_proxy_status_service::ProxyStatusServiceClient as RemoteProverProxyStatusClient;
pub use services::miden_sequencer_v1_sequencer_service::SequencerServiceClient as SequencerClient;
pub use services::miden_validator_v1_validator_service::ValidatorServiceClient as ValidatorClient;

// TYPE-SAFE CLIENT BUILDER
// ================================================================================================

/// A type-safe builder that forces the caller to make an explicit decision for each
/// configuration item (TLS, metadata version, metadata genesis) before connecting.
///
/// RPCs default to [`DEFAULT_REQUEST_TIMEOUT`], configurable with [`Builder::with_timeout`].
/// Received messages default to a 4 MiB limit, configurable with
/// [`Builder::max_decoding_message_size`].
///
/// Usage example:
///
/// ```rust
/// # use miden_node_proto::clients::{Builder, WantsTls, RpcClient};
/// # use url::Url;
/// # use std::time::Duration;
///
/// # async fn example() -> anyhow::Result<()> {
/// let url = Url::parse("https://rpc.example.com:8080")?;
/// let client: RpcClient = Builder::new(url)
///     .with_tls()?                          // or `.without_tls()`
///     .with_timeout(Duration::from_secs(5))
///     .with_metadata_version("1.0".into())  // or `.without_metadata_version()`
///     .without_metadata_genesis()           // or `.with_metadata_genesis(genesis)`
///     .without_auth_header()                // or `.with_auth_header_value(AsciiMetadataValue::from_static("value"))`
///     .with_otel_context_injection()        // or `.without_otel_context_injection()`
///     .connect::<RpcClient>()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Builder<State> {
    endpoint: Endpoint,
    request_timeout: Duration,
    endpoint_url: Url,
    max_decoding_message_size: usize,
    metadata_version: Option<String>,
    metadata_genesis: Option<Word>,
    metadata_auth_header_value: Option<AsciiMetadataValue>,
    enable_otel: bool,
    _state: PhantomData<State>,
}

#[derive(Copy, Clone, Debug)]
pub struct WantsTls;
#[derive(Copy, Clone, Debug)]
pub struct WantsVersion;
#[derive(Copy, Clone, Debug)]
pub struct WantsGenesis;
#[derive(Copy, Clone, Debug)]
pub struct WantsOTel;
#[derive(Copy, Clone, Debug)]
pub struct WantsConnection;

impl<State> Builder<State> {
    /// Overrides the default deadline for complete unary RPCs and subscription establishment.
    ///
    /// Defaults to [`DEFAULT_REQUEST_TIMEOUT`]. Connection setup uses the same budget.
    /// A client's `with_timeout` changes its RPC budget without changing other clones.
    #[must_use]
    pub fn with_timeout(mut self, duration: Duration) -> Self {
        assert!(!duration.is_zero(), "gRPC deadline must be positive");
        self.request_timeout = duration;
        self.endpoint = self.endpoint.connect_timeout(duration);
        self
    }

    /// Sets the maximum encoded size of a received response or stream item.
    #[must_use]
    pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
        self.max_decoding_message_size = limit;
        self
    }

    /// Convenience function to cast the state type and carry internal configuration forward.
    fn next_state<Next>(self) -> Builder<Next> {
        Builder {
            endpoint: self.endpoint,
            request_timeout: self.request_timeout,
            endpoint_url: self.endpoint_url,
            max_decoding_message_size: self.max_decoding_message_size,
            metadata_version: self.metadata_version,
            metadata_genesis: self.metadata_genesis,
            metadata_auth_header_value: self.metadata_auth_header_value,
            enable_otel: self.enable_otel,
            _state: PhantomData::<Next>,
        }
    }
}

/// Client HTTP/2 keepalive interval.
const HTTP2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
/// Client HTTP/2 keepalive: how long to wait for a PING ack before considering the connection dead.
const HTTP2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// OS-level TCP keepalive backstop for direct (non-proxied) connections.
const TCP_KEEPALIVE: Duration = Duration::from_secs(30);

impl Builder<WantsTls> {
    /// Create a new strict builder from a gRPC endpoint URL such as `http://localhost:8080` or
    /// `https://api.example.com:443`.
    pub fn new(url: Url) -> Builder<WantsTls> {
        let endpoint = Endpoint::from_shared(String::from(url.clone()))
            .expect("Url type always results in valid endpoint")
            // Detect silently dropped connections so long-lived streams can't hang forever; see the
            // keepalive constants above.
            .http2_keep_alive_interval(HTTP2_KEEPALIVE_INTERVAL)
            .keep_alive_timeout(HTTP2_KEEPALIVE_TIMEOUT)
            .keep_alive_while_idle(true)
            .tcp_keepalive(Some(TCP_KEEPALIVE))
            .connect_timeout(DEFAULT_REQUEST_TIMEOUT);

        Builder {
            endpoint,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            endpoint_url: url,
            max_decoding_message_size: DEFAULT_MAX_DECODING_MESSAGE_SIZE,
            metadata_version: None,
            metadata_genesis: None,
            metadata_auth_header_value: None,
            enable_otel: false,
            _state: PhantomData,
        }
    }

    /// Explicitly disable TLS.
    pub fn without_tls(self) -> Builder<WantsVersion> {
        self.next_state()
    }

    /// Explicitly enable TLS.
    pub fn with_tls(mut self) -> Result<Builder<WantsVersion>, TransportError> {
        self.endpoint = self.endpoint.tls_config(ClientTlsConfig::new().with_native_roots())?;

        Ok(self.next_state())
    }
}

impl Builder<WantsVersion> {
    /// Do not include version in request metadata.
    pub fn without_metadata_version(mut self) -> Builder<WantsGenesis> {
        self.metadata_version = None;
        self.next_state()
    }

    /// Include a specific version string in request metadata.
    pub fn with_metadata_version(mut self, version: String) -> Builder<WantsGenesis> {
        self.metadata_version = Some(version);
        self.next_state()
    }
}

impl Builder<WantsGenesis> {
    /// Do not include genesis commitment in request metadata.
    pub fn without_metadata_genesis(mut self) -> Builder<WantsOTel> {
        self.metadata_genesis = None;
        self.next_state()
    }

    /// Include a specific genesis commitment in request metadata.
    pub fn with_metadata_genesis(mut self, genesis: Word) -> Builder<WantsOTel> {
        self.metadata_genesis = Some(genesis);
        self.next_state()
    }
}

impl Builder<WantsOTel> {
    /// Do not include any additional metadata header in request metadata.
    #[must_use]
    pub fn without_auth_header(mut self) -> Self {
        self.metadata_auth_header_value = None;
        self
    }

    /// Include an additional ASCII metadata header in request metadata.
    #[must_use]
    pub fn with_auth_header_value(mut self, value: AsciiMetadataValue) -> Self {
        self.metadata_auth_header_value = Some(value);
        self
    }

    /// Enables OpenTelemetry context propagation via gRPC.
    ///
    /// This is used to by OpenTelemetry to connect traces across network boundaries. The server on
    /// the other end must be configured to receive and use the injected trace context.
    pub fn with_otel_context_injection(mut self) -> Builder<WantsConnection> {
        self.enable_otel = true;
        self.next_state()
    }

    /// Disables OpenTelemetry context propagation. This should be disabled when interfacing with
    /// external third party gRPC servers.
    pub fn without_otel_context_injection(mut self) -> Builder<WantsConnection> {
        self.enable_otel = false;
        self.next_state()
    }
}

impl Builder<WantsConnection> {
    /// Establish an eager connection and return a fully configured client.
    pub async fn connect<T>(self) -> Result<T, Status>
    where
        T: GrpcClient,
    {
        let channel = tokio::time::timeout(self.request_timeout, self.endpoint.connect())
            .await
            .map_err(|_| Status::deadline_exceeded("gRPC connection deadline expired"))?
            .map_err(|error| Status::from_error(Box::new(error)))?;
        Ok(self.connect_with_channel::<T>(channel))
    }

    /// Establish a lazy connection and return a client that will connect on first use.
    pub fn connect_lazy<T>(self) -> T
    where
        T: GrpcClient,
    {
        let channel = self.endpoint.connect_lazy();
        self.connect_with_channel::<T>(channel)
    }

    /// Monitors whether the configured endpoint can establish a transport connection.
    ///
    /// The monitor is non-blocking with respect to service startup. It warns on the first failed
    /// attempt, retries with capped exponential backoff, and reports when the dependency becomes
    /// reachable. Once connected it waits for shutdown instead of creating duplicate connections.
    pub async fn monitor<T>(
        self,
        dependency_name: &'static str,
        shutdown: miden_node_utils::shutdown::CancellationToken,
    ) where
        T: GrpcClient + Send + 'static,
    {
        const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
        const RETRY_MIN: Duration = Duration::from_secs(1);
        const RETRY_MAX: Duration = Duration::from_secs(30);

        use miden_node_utils::retry::BackoffBuilder;

        let endpoint = miden_node_utils::formatting::format_endpoint(&self.endpoint_url);
        let mut backoff = miden_node_utils::retry::exponential(RETRY_MIN, RETRY_MAX).build();
        let mut first_failure = true;

        loop {
            let attempt = tokio::time::timeout(CONNECT_TIMEOUT, self.clone().connect::<T>());
            let result = tokio::select! {
                () = shutdown.cancelled() => return,
                result = attempt => result,
            };

            match result {
                Ok(Ok(_client)) => {
                    info!(
                        "Configured service reachable",
                        dependency.name = dependency_name,
                        dependency.endpoint = endpoint.as_str()
                    );
                    shutdown.cancelled().await;
                    return;
                },
                Ok(Err(err)) if first_failure => {
                    warn!(
                        &err,
                        "Configured service unreachable",
                        dependency.name = dependency_name,
                        dependency.endpoint = endpoint.as_str()
                    );
                },
                Err(_elapsed) if first_failure => {
                    warn!(
                        "Configured service connection timed out",
                        dependency.name = dependency_name,
                        dependency.endpoint = endpoint.as_str(),
                        timeout.ms = CONNECT_TIMEOUT
                    );
                },
                Ok(Err(err)) => {
                    debug!(
                        &err,
                        "Configured service still unreachable",
                        dependency.name = dependency_name,
                        dependency.endpoint = endpoint.as_str()
                    );
                },
                Err(_elapsed) => {
                    debug!(
                        "Configured service connection still timing out",
                        dependency.name = dependency_name,
                        dependency.endpoint = endpoint.as_str(),
                        timeout.ms = CONNECT_TIMEOUT
                    );
                },
            }
            first_failure = false;

            let retry_delay = backoff.next().unwrap_or(RETRY_MAX);
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(retry_delay) => {},
            }
        }
    }

    fn connect_with_channel<T>(self, channel: Channel) -> T
    where
        T: GrpcClient,
    {
        let metadata_genesis = self.metadata_genesis.map(|genesis| genesis.to_hex());
        let interceptor = Interceptor::new(
            self.enable_otel,
            self.metadata_version.as_deref(),
            metadata_genesis.as_deref(),
            self.metadata_auth_header_value,
        );
        let channel = RecoveringChannel::new(self.endpoint, channel);
        T::with_interceptor(channel, interceptor)
            .with_timeout(self.request_timeout)
            .max_decoding_message_size(self.max_decoding_message_size)
    }
}

impl ValidatorClient {
    /// Submits each transaction in the batch to the validator for re-execution, retrying transient
    /// failures for each transaction independently with a fresh request budget per attempt.
    ///
    /// # Errors
    ///
    /// - If `sealed_transaction_inputs` does not match the batch's transactions in length
    pub async fn submit_batch(
        &self,
        proposed_batch: &ProposedBatch,
        sealed_transaction_inputs: &[SealedTransactionInputs],
    ) -> Result<(), Status> {
        if proposed_batch.transactions().len() != sealed_transaction_inputs.len() {
            return Err(Status::invalid_argument(
                "transaction inputs do not match the batch's transactions",
            ));
        }
        for (tx, inputs) in proposed_batch.transactions().iter().zip(sealed_transaction_inputs) {
            let proven_tx = GeneratedProvenTransaction {
                transaction: Some(tx.as_ref().into()),
                sealed_transaction_inputs: Some(inputs.clone()),
            };
            (|| async {
                self.clone()
                    .submit_proven_transaction(
                        crate::generated::miden::validator::v1::SubmitProvenTransactionRequest {
                            submission: Some(proven_tx.clone()),
                        },
                    )
                    .await
            })
            .retry_transient()
            .await?;
        }
        Ok(())
    }
}
