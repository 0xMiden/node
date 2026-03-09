use std::time::Duration;

use anyhow::{Context, ensure};
use governor::middleware::StateInformationMiddleware;
use tonic::service::InterceptorLayer;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::SmartIpKeyExtractor;

use super::connect_info::ConnectInfoInterceptor;
use crate::clap::GrpcOptionsExternal;

/// Creates the gRPC interceptor layer that attaches connection metadata.
pub fn connect_info_layer() -> InterceptorLayer<ConnectInfoInterceptor> {
    InterceptorLayer::new(ConnectInfoInterceptor)
}

/// Builds a global concurrency limit layer using the configured semaphore.
pub fn rate_limit_concurrent_connections(
    grpc_options: GrpcOptionsExternal,
) -> GlobalConcurrencyLimitLayer {
    tower::limit::GlobalConcurrencyLimitLayer::new(
        grpc_options.max_global_concurrent_connections as usize,
    )
}

/// Creates a per-IP rate limit layer using the configured governor settings.
pub fn rate_limit_per_ip(
    grpc_options: GrpcOptionsExternal,
) -> anyhow::Result<
    tower_governor::GovernorLayer<
        SmartIpKeyExtractor,
        StateInformationMiddleware,
        tonic::body::Body,
    >,
> {
    let nanos_per_replenish = Duration::from_secs(1)
        .as_nanos()
        .checked_div(u128::from(grpc_options.replenish_n_per_second_per_ip.get()))
        .unwrap_or_default();
    ensure!(
        nanos_per_replenish > 0,
        "grpc.replenish_n_per_second must be less than or equal to 1e9"
    );
    let replenish_period = Duration::from_nanos(
        u64::try_from(nanos_per_replenish).context("invalid gRPC rate limit configuration")?,
    );
    let config = GovernorConfigBuilder::default()
        .key_extractor(SmartIpKeyExtractor)
        .period(replenish_period)
        .burst_size(grpc_options.burst_size.into())
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
