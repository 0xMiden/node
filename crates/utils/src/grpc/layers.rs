use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, ensure};
use governor::middleware::StateInformationMiddleware;
use tokio::sync::Semaphore;
use tonic::service::InterceptorLayer;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::SmartIpKeyExtractor;

use super::connect_info::ConnectInfoInterceptor;
use crate::clap::GrpcOptions;

/// Creates the gRPC interceptor layer that attaches connection metadata.
pub fn connect_info_layer() -> InterceptorLayer<ConnectInfoInterceptor> {
    InterceptorLayer::new(ConnectInfoInterceptor)
}

/// Builds a global concurrency limit layer using the configured semaphore.
pub fn rate_limit_concurrent_connections(grpc_options: GrpcOptions) -> GlobalConcurrencyLimitLayer {
    tower::limit::GlobalConcurrencyLimitLayer::with_semaphore(concurrency_semaphore(grpc_options))
}

/// Builds the shared semaphore that caps total concurrent gRPC connections.
pub fn concurrency_semaphore(grpc_options: GrpcOptions) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(
        (grpc_options.max_global_concurrent_connections as usize).min(Semaphore::MAX_PERMITS),
    ))
}

/// Builds a global concurrency limit layer from an existing semaphore.
pub fn rate_limit_with_semaphore(sema: Arc<Semaphore>) -> GlobalConcurrencyLimitLayer {
    tower::limit::GlobalConcurrencyLimitLayer::with_semaphore(sema)
}

/// Creates a per-IP rate limit layer using the configured governor settings.
pub fn rate_limit_per_ip(
    grpc_options: GrpcOptions,
) -> anyhow::Result<
    tower_governor::GovernorLayer<
        SmartIpKeyExtractor,
        StateInformationMiddleware,
        tonic::body::Body,
    >,
> {
    ensure!(
        grpc_options.replenish_per_sec > 0,
        "grpc.replenish_per_sec must be greater than zero"
    );
    ensure!(
        grpc_options.burst_size > 0,
        "grpc.burst_size must be greater than zero"
    );
    let config = GovernorConfigBuilder::default()
        .key_extractor(SmartIpKeyExtractor)
        .per_second(grpc_options.replenish_per_sec)
        .burst_size(grpc_options.burst_size as u32)
        .use_headers()
        .finish()
        .context("invalid gRPC rate limit configuration")?;
    let limiter = std::sync::Arc::clone(config.limiter());
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            // avoid a DoS vector
            limiter.retain_recent();
        }
    });
    Ok(tower_governor::GovernorLayer::new(config))
}
