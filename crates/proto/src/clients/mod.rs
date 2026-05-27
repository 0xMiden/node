//! gRPC client builder utilities for Miden node.
//!
//! This module provides a unified type-safe [`Builder`] for creating various gRPC clients with
//! explicit configuration decisions for TLS, timeout, and metadata.
//!
//! # Examples
//!
//! ```rust
//! # use miden_node_proto::clients::{Builder, WantsTls, StoreRpcClient};
//! # use url::Url;
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Create a store client with OTEL and TLS
//! let url = Url::parse("https://example.com:8080")?;
//! let client: StoreRpcClient = Builder::new(url)
//!     .with_tls()?                   // or `.without_tls()`
//!     .without_timeout()             // or `.with_timeout(Duration::from_secs(10))`
//!     .without_metadata_version()    // or `.with_metadata_version("1.0".into())`
//!     .without_metadata_genesis()    // or `.with_metadata_genesis(genesis)`
//!     .without_auth_header()         // or `.with_auth_header_value(AsciiMetadataValue::from_static("value"))`
//!     .with_otel_context_injection() // or `.without_otel_context_injection()`
//!     .connect::<StoreRpcClient>()
//!     .await?;
//! # Ok(())
//! # }
//! ```

use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use http::header::ACCEPT;
use miden_node_utils::tracing::grpc::OtelInterceptor;
use tonic::metadata::AsciiMetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{Request, Status};
use url::Url;

use crate::generated;

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
                "{}; {}={version}, {}={genesis}",
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

        request.metadata_mut().insert(ACCEPT.as_str(), self.accept.clone());

        if let Some(value) = &self.auth_header_value {
            request.metadata_mut().insert(Self::NETWORK_TX_AUTH_HEADER_NAME, value.clone());
        }

        Ok(request)
    }
}

// TYPE ALIASES TO AID LEGIBILITY
// ================================================================================================

type InterceptedChannel = InterceptedService<Channel, Interceptor>;
type GeneratedRpcClient = generated::rpc::api_client::ApiClient<InterceptedChannel>;
type GeneratedStoreClientForBlockProducer =
    generated::store::block_producer_client::BlockProducerClient<InterceptedChannel>;
type GeneratedStoreClientForRpc = generated::store::rpc_client::RpcClient<InterceptedChannel>;
type GeneratedProxyStatusClient =
    generated::remote_prover::proxy_status_api_client::ProxyStatusApiClient<InterceptedChannel>;
type GeneratedProverClient = generated::remote_prover::api_client::ApiClient<InterceptedChannel>;
type GeneratedValidatorClient = generated::validator::api_client::ApiClient<InterceptedChannel>;
type GeneratedNtxBuilderClient = generated::ntx_builder::api_client::ApiClient<InterceptedChannel>;

// gRPC CLIENTS
// ================================================================================================

#[derive(Debug, Clone)]
pub struct RpcClient(GeneratedRpcClient);
#[derive(Debug, Clone)]
pub struct StoreBlockProducerClient(GeneratedStoreClientForBlockProducer);
#[derive(Debug, Clone)]
pub struct StoreRpcClient(GeneratedStoreClientForRpc);
#[derive(Debug, Clone)]
pub struct RemoteProverProxyStatusClient(GeneratedProxyStatusClient);
#[derive(Debug, Clone)]
pub struct RemoteProverClient(GeneratedProverClient);
#[derive(Debug, Clone)]
pub struct ValidatorClient(GeneratedValidatorClient);
#[derive(Debug, Clone)]
pub struct NtxBuilderClient(GeneratedNtxBuilderClient);

impl DerefMut for RpcClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for RpcClient {
    type Target = GeneratedRpcClient;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for StoreBlockProducerClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for StoreBlockProducerClient {
    type Target = GeneratedStoreClientForBlockProducer;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for StoreRpcClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for StoreRpcClient {
    type Target = GeneratedStoreClientForRpc;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RemoteProverProxyStatusClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for RemoteProverProxyStatusClient {
    type Target = GeneratedProxyStatusClient;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RemoteProverClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for RemoteProverClient {
    type Target = GeneratedProverClient;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ValidatorClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for ValidatorClient {
    type Target = GeneratedValidatorClient;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for NtxBuilderClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for NtxBuilderClient {
    type Target = GeneratedNtxBuilderClient;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// GRPC CLIENT BUILDER TRAIT
// ================================================================================================

/// Trait for building gRPC clients from a common [`Builder`] configuration.
pub trait GrpcClient {
    fn with_interceptor(channel: Channel, interceptor: Interceptor) -> Self;
}

impl GrpcClient for RpcClient {
    fn with_interceptor(channel: Channel, interceptor: Interceptor) -> Self {
        Self(GeneratedRpcClient::new(InterceptedService::new(channel, interceptor)))
    }
}

impl GrpcClient for StoreBlockProducerClient {
    fn with_interceptor(channel: Channel, interceptor: Interceptor) -> Self {
        Self(GeneratedStoreClientForBlockProducer::new(InterceptedService::new(
            channel,
            interceptor,
        )))
    }
}

impl GrpcClient for StoreRpcClient {
    fn with_interceptor(channel: Channel, interceptor: Interceptor) -> Self {
        Self(GeneratedStoreClientForRpc::new(InterceptedService::new(channel, interceptor)))
    }
}

impl GrpcClient for RemoteProverProxyStatusClient {
    fn with_interceptor(channel: Channel, interceptor: Interceptor) -> Self {
        Self(GeneratedProxyStatusClient::new(InterceptedService::new(channel, interceptor)))
    }
}

impl GrpcClient for RemoteProverClient {
    fn with_interceptor(channel: Channel, interceptor: Interceptor) -> Self {
        Self(GeneratedProverClient::new(InterceptedService::new(channel, interceptor)))
    }
}

impl GrpcClient for ValidatorClient {
    fn with_interceptor(channel: Channel, interceptor: Interceptor) -> Self {
        Self(GeneratedValidatorClient::new(InterceptedService::new(channel, interceptor)))
    }
}

impl GrpcClient for NtxBuilderClient {
    fn with_interceptor(channel: Channel, interceptor: Interceptor) -> Self {
        Self(GeneratedNtxBuilderClient::new(InterceptedService::new(channel, interceptor)))
    }
}

// STRICT TYPE-SAFE BUILDER (NO DEFAULTS)
// ================================================================================================

/// A type-safe builder that forces the caller to make an explicit decision for each
/// configuration item (TLS, timeout, metadata version, metadata genesis) before connecting.
///
/// This builder replaces the previous defaulted builder. Callers must explicitly choose TLS,
/// timeout, and metadata options before connecting.
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
///     .with_timeout(Duration::from_secs(5)) // or `.without_timeout()`
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
    metadata_version: Option<String>,
    metadata_genesis: Option<String>,
    metadata_auth_header_value: Option<AsciiMetadataValue>,
    enable_otel: bool,
    _state: PhantomData<State>,
}

#[derive(Copy, Clone, Debug)]
pub struct WantsTls;
#[derive(Copy, Clone, Debug)]
pub struct WantsTimeout;
#[derive(Copy, Clone, Debug)]
pub struct WantsVersion;
#[derive(Copy, Clone, Debug)]
pub struct WantsGenesis;
#[derive(Copy, Clone, Debug)]
pub struct WantsAuthHeader;
#[derive(Copy, Clone, Debug)]
pub struct WantsOTel;
#[derive(Copy, Clone, Debug)]
pub struct WantsConnection;

impl<State> Builder<State> {
    /// Convenience function to cast the state type and carry internal configuration forward.
    fn next_state<Next>(self) -> Builder<Next> {
        Builder {
            endpoint: self.endpoint,
            metadata_version: self.metadata_version,
            metadata_genesis: self.metadata_genesis,
            metadata_auth_header_value: self.metadata_auth_header_value,
            enable_otel: self.enable_otel,
            _state: PhantomData::<Next>,
        }
    }
}

impl Builder<WantsTls> {
    /// Create a new strict builder from a gRPC endpoint URL such as `http://localhost:8080` or
    /// `https://api.example.com:443`.
    pub fn new(url: Url) -> Builder<WantsTls> {
        let endpoint = Endpoint::from_shared(String::from(url))
            .expect("Url type always results in valid endpoint");

        Builder {
            endpoint,
            metadata_version: None,
            metadata_genesis: None,
            metadata_auth_header_value: None,
            enable_otel: false,
            _state: PhantomData,
        }
    }

    /// Explicitly disable TLS.
    pub fn without_tls(self) -> Builder<WantsTimeout> {
        self.next_state()
    }

    /// Explicitly enable TLS.
    pub fn with_tls(mut self) -> Result<Builder<WantsTimeout>> {
        self.endpoint = self
            .endpoint
            .tls_config(ClientTlsConfig::new().with_native_roots())
            .context("Failed to configure TLS")?;

        Ok(self.next_state())
    }
}

impl Builder<WantsTimeout> {
    /// Explicitly disable request timeout.
    pub fn without_timeout(self) -> Builder<WantsVersion> {
        self.next_state()
    }

    /// Explicitly configure a request timeout.
    pub fn with_timeout(mut self, duration: Duration) -> Builder<WantsVersion> {
        self.endpoint = self.endpoint.timeout(duration);
        self.next_state()
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
    pub fn without_metadata_genesis(mut self) -> Builder<WantsAuthHeader> {
        self.metadata_genesis = None;
        self.next_state()
    }

    /// Include a specific genesis commitment string in request metadata.
    pub fn with_metadata_genesis(mut self, genesis: String) -> Builder<WantsAuthHeader> {
        self.metadata_genesis = Some(genesis);
        self.next_state()
    }
}

impl Builder<WantsAuthHeader> {
    /// Do not include any additional metadata header in request metadata.
    pub fn without_auth_header(mut self) -> Builder<WantsOTel> {
        self.metadata_auth_header_value = None;
        self.next_state()
    }

    /// Include an additional ASCII metadata header in request metadata.
    pub fn with_auth_header_value(mut self, value: AsciiMetadataValue) -> Builder<WantsOTel> {
        self.metadata_auth_header_value = Some(value);
        self.next_state()
    }

    /// Enables OpenTelemetry context propagation via gRPC without adding a metadata header.
    pub fn with_otel_context_injection(mut self) -> Builder<WantsConnection> {
        self.enable_otel = true;
        self.next_state()
    }

    /// Disables OpenTelemetry context propagation without adding a metadata header.
    pub fn without_otel_context_injection(mut self) -> Builder<WantsConnection> {
        self.enable_otel = false;
        self.next_state()
    }
}

impl Builder<WantsOTel> {
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
    pub async fn connect<T>(self) -> Result<T>
    where
        T: GrpcClient,
    {
        let channel = self.endpoint.connect().await?;
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

    fn connect_with_channel<T>(self, channel: Channel) -> T
    where
        T: GrpcClient,
    {
        let interceptor = Interceptor::new(
            self.enable_otel,
            self.metadata_version.as_deref(),
            self.metadata_genesis.as_deref(),
            self.metadata_auth_header_value,
        );
        T::with_interceptor(channel, interceptor)
    }
}

#[cfg(test)]
mod tests {
    use tonic::metadata::AsciiMetadataValue;
    use tonic::service::Interceptor as _;
    use url::Url;

    use super::{Builder, Interceptor};

    #[test]
    fn interceptor_inserts_only_accept_by_default() {
        let mut interceptor = Interceptor::default();
        let request = interceptor.call(tonic::Request::new(())).unwrap();

        assert!(request.metadata().get("accept").is_some());
        assert!(request.metadata().get("x-miden-network-tx-auth").is_none());
    }

    #[test]
    fn interceptor_inserts_custom_ascii_auth_metadata_when_configured() {
        let mut interceptor = Interceptor::new(
            false,
            None,
            None,
            Some(AsciiMetadataValue::from_static("secret-value")),
        );

        let request = interceptor.call(tonic::Request::new(())).unwrap();

        assert_eq!(
            request.metadata().get("x-miden-network-tx-auth").unwrap().to_str().unwrap(),
            "secret-value"
        );
    }

    #[test]
    fn interceptor_inserts_existing_post_genesis_chain_can_skip_metadata_header() {
        let url = Url::parse("http://localhost:8080").unwrap();

        let _ = Builder::new(url)
            .without_tls()
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .without_otel_context_injection();
    }
}
