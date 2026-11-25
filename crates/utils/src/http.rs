//! HTTP clients for outgoing requests.
//!
//! Use [`get`] for a one-off download or reuse a [`Client`] across requests. Configure timeouts
//! and redirect policies with [`Client::builder`].

use std::time::Duration;

use http::HeaderMap;
pub use http::StatusCode;
use miden_node_tracing::{Instrument as _, Span, field, info_span};

/// An HTTP client or response error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct Error(reqwest::Error);

impl Error {
    #[must_use]
    pub fn without_url(self) -> Self {
        Self(self.0.without_url())
    }
}

/// A reusable HTTP client that traces requests through response consumption.
#[derive(Clone, Debug, Default)]
pub struct Client(reqwest::Client);

impl Client {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder() -> ClientBuilder {
        ClientBuilder(reqwest::Client::builder())
    }

    pub fn get(&self, url: impl AsRef<str>) -> RequestBuilder {
        RequestBuilder(self.0.get(url.as_ref()))
    }

    pub fn post(&self, url: impl AsRef<str>) -> RequestBuilder {
        RequestBuilder(self.0.post(url.as_ref()))
    }

    pub fn put(&self, url: impl AsRef<str>) -> RequestBuilder {
        RequestBuilder(self.0.put(url.as_ref()))
    }
}

/// Configures a shared HTTP client before opening connections.
#[must_use]
pub struct ClientBuilder(reqwest::ClientBuilder);

impl ClientBuilder {
    pub fn timeout(self, timeout: Duration) -> Self {
        Self(self.0.timeout(timeout))
    }

    pub fn connect_timeout(self, timeout: Duration) -> Self {
        Self(self.0.connect_timeout(timeout))
    }

    pub fn without_redirects(self) -> Self {
        Self(self.0.redirect(reqwest::redirect::Policy::none()))
    }

    pub fn build(self) -> Result<Client, Error> {
        self.0.build().map(Client).map_err(Error)
    }
}

/// Sends a one-off traced GET request.
pub async fn get(url: impl AsRef<str>) -> Result<Response, Error> {
    Client::builder().build()?.get(url).send().await
}

/// A request sent through the shared HTTP client.
#[must_use]
pub struct RequestBuilder(reqwest::RequestBuilder);

impl RequestBuilder {
    pub fn headers(self, headers: HeaderMap) -> Self {
        Self(self.0.headers(headers))
    }

    pub fn header(self, name: &str, value: &str) -> Self {
        Self(self.0.header(name, value))
    }

    pub fn body(self, body: Vec<u8>) -> Self {
        Self(self.0.body(body))
    }

    pub fn timeout(self, timeout: Duration) -> Self {
        Self(self.0.timeout(timeout))
    }

    pub fn json<T: serde::Serialize + ?Sized>(self, body: &T) -> Self {
        Self(self.0.json(body))
    }

    /// Sends a request and keeps its client span open while the caller reads the response.
    ///
    /// Only the method, host, port, and response status are recorded. URLs can contain account
    /// identifiers, credentials, and provider keys.
    pub async fn send(self) -> Result<Response, Error> {
        let (client, request) = self.0.build_split();
        let request = request.map_err(Error)?;
        let method = request.method().as_str();
        let span = info_span!(
            "request",
            otel.kind = "client",
            otel.name = method,
            http.request.method = method,
            server.address = request.url().host_str(),
            server.port = request.url().port_or_known_default().map(i64::from),
            http.response.status_code = field::Empty,
            otel.status_code = field::Empty,
        );
        let response = client
            .execute(request)
            .instrument(span.clone())
            .await
            .inspect_err(|_| {
                span.record("otel.status_code", "ERROR");
            })
            .map_err(Error)?;
        let status = response.status();
        span.record("http.response.status_code", i64::from(status.as_u16()));
        if status.is_client_error() || status.is_server_error() {
            span.record("otel.status_code", "ERROR");
        }
        Ok(Response { response, span })
    }
}

/// Keeps the HTTP client span open until the response is consumed or dropped.
pub struct Response {
    response: reqwest::Response,
    span: Span,
}

impl Response {
    pub fn headers(&self) -> &HeaderMap {
        self.response.headers()
    }

    pub fn status(&self) -> StatusCode {
        self.response.status()
    }

    pub fn error_for_status(self) -> Result<Self, Error> {
        self.response.error_for_status_ref().map_err(Error)?;
        Ok(self)
    }

    pub async fn text(self) -> Result<String, Error> {
        read_body(self.span, self.response.text()).await
    }

    pub async fn bytes(self) -> Result<axum::body::Bytes, Error> {
        read_body(self.span, self.response.bytes()).await
    }

    pub async fn json<T: serde::de::DeserializeOwned>(self) -> Result<T, Error> {
        read_body(self.span, self.response.json()).await
    }
}

async fn read_body<T>(
    span: Span,
    read: impl Future<Output = reqwest::Result<T>>,
) -> Result<T, Error> {
    read.instrument(span.clone())
        .await
        .inspect_err(|_| {
            span.record("otel.status_code", "ERROR");
        })
        .map_err(Error)
}
