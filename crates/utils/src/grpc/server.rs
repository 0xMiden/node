use std::time::Duration;

use tokio::net::TcpListener;
use tonic::transport::Server;
use tonic::transport::server::TcpIncoming;

const HTTP2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);
const HTTP2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const TCP_KEEPALIVE_RETRIES: u32 = 3;

/// Creates a gRPC server builder with HTTP/2 liveness checks.
///
/// A peer must acknowledge keepalive PINGs even when no application data is available.
pub fn server_builder() -> Server {
    Server::builder()
        .http2_keepalive_interval(Some(HTTP2_KEEPALIVE_INTERVAL))
        .http2_keepalive_timeout(Some(HTTP2_KEEPALIVE_TIMEOUT))
}

/// Creates an incoming stream with TCP liveness checks on accepted sockets.
///
/// TCP probes cover HTTP/1 connections as well as HTTP/2 connections. Tonic ignores its server TCP
/// settings when the caller supplies an incoming stream. Some platforms use their system defaults
/// for the probe interval or retry count.
pub fn tcp_incoming(listener: TcpListener) -> TcpIncoming {
    TcpIncoming::from(listener)
        .with_keepalive(Some(TCP_KEEPALIVE_IDLE))
        .with_keepalive_interval(Some(TCP_KEEPALIVE_INTERVAL))
        .with_keepalive_retries(Some(TCP_KEEPALIVE_RETRIES))
}
