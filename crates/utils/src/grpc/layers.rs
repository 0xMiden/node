use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use governor::middleware::StateInformationMiddleware;
use tokio::sync::Semaphore;
use tonic::service::InterceptorLayer;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::SmartIpKeyExtractor;

use super::connect_info::ConnectInfoInterceptor;
use crate::clap::GrpcOptions;

pub fn connect_info_layer() -> InterceptorLayer<ConnectInfoInterceptor> {
    InterceptorLayer::new(ConnectInfoInterceptor)
}

pub fn rate_limit_concurrent_connections(grpc_options: GrpcOptions) -> GlobalConcurrencyLimitLayer {
    // TODO this uses a semaphore internally, and we should strive to move to an `AtomicU64` with
    // ordering relaxed
    tower::limit::GlobalConcurrencyLimitLayer::with_semaphore(rate_limit_with_semaphore(
        grpc_options,
    ))
}

pub fn rate_limit_with_semaphore(grpc_options: GrpcOptions) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(
        (grpc_options.max_global_concurrent_connections as usize).min(Semaphore::MAX_PERMITS),
    ))
}

pub fn rate_limit_concurrent_connections_with_semaphore(
    sema: Arc<Semaphore>,
) -> GlobalConcurrencyLimitLayer {
    tower::limit::GlobalConcurrencyLimitLayer::with_semaphore(sema)
}

pub fn rate_limit_per_ip(
    grpc_options: GrpcOptions,
) -> anyhow::Result<
    tower_governor::GovernorLayer<
        SmartIpKeyExtractor,
        StateInformationMiddleware,
        tonic::body::Body,
    >,
> {
    let config = GovernorConfigBuilder::default()
        .key_extractor(SmartIpKeyExtractor)
        .per_second(grpc_options.replenish_per_sec)
        .burst_size(grpc_options.burst_size as u32)
        .use_headers()
        .finish()
        .context("config parameters are inconsistent, i.e. burst < per second")?;
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
