//! Polls the funding service's status endpoint for account and native asset information.

use std::time::Duration;

use miden_node_tracing::miden_instrument;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::COMPONENT;
use crate::service::Service;
use crate::status::{FundingStatusDetails, ServiceDetails, ServiceStatus};

/// The account state reported by the funding service's `GET /status` endpoint.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FundingStatusResponse {
    pub version: String,
    pub account_id: String,
    pub native_asset: NativeAsset,
    pub balance: u64,
    pub chain_tip: u32,
    pub max_amount: u64,
    pub verification_base_fee: u32,
}

/// Metadata for the native asset distributed by the funding service.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NativeAsset {
    pub asset_id: String,
    pub symbol: String,
    pub decimals: u8,
    pub name: String,
}

/// Checks funding service availability without requesting funds.
pub struct FundingService {
    url: Url,
    client: Client,
    interval: Duration,
    request_timeout: Duration,
}

impl FundingService {
    pub fn new(url: Url, interval: Duration, request_timeout: Duration) -> Self {
        Self {
            url,
            client: Client::new(),
            interval,
            request_timeout,
        }
    }

    async fn fetch_status(&self) -> anyhow::Result<FundingStatusResponse> {
        Ok(self
            .client
            .get(self.url.join("status")?)
            .timeout(self.request_timeout)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}

impl Service for FundingService {
    fn name(&self) -> &'static str {
        "Funding Service"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn initial_status(&self) -> ServiceStatus {
        ServiceStatus::unknown(
            self.name(),
            ServiceDetails::FundingStatus(FundingStatusDetails {
                url: self.url.to_string(),
                status: None,
            }),
        )
    }

    #[miden_instrument(target = COMPONENT, name = "check-status.funding-service")]
    async fn check(&mut self) -> ServiceStatus {
        let mut details = FundingStatusDetails { url: self.url.to_string(), status: None };
        match self.fetch_status().await {
            Ok(status) => {
                details.status = Some(status);
                ServiceStatus::healthy(self.name(), ServiceDetails::FundingStatus(details))
            },
            Err(error) => ServiceStatus::unhealthy(
                self.name(),
                format!("{error:#}"),
                ServiceDetails::FundingStatus(details),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::get;
    use tokio::sync::watch;

    use super::*;
    use crate::status::Status;

    const RESPONSE: &str = r#"{
        "version": "1.2.3",
        "account_id": "0x1234",
        "native_asset": {"asset_id": "0xabcd", "symbol": "MIDEN", "decimals": 6, "name": "Miden"},
        "balance": 0,
        "chain_tip": 42,
        "max_amount": 1000000000,
        "verification_base_fee": 7
    }"#;

    #[tokio::test]
    async fn funding_status_handles_failures_and_recovers() {
        let (tx, rx) = watch::channel((StatusCode::OK, RESPONSE));
        let app = Router::new().route(
            "/status",
            get(move || {
                let response = *rx.borrow();
                async move { response }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut service =
            FundingService::new(url.clone(), Duration::from_secs(1), Duration::from_secs(5));

        let initial = service.initial_status();
        assert_eq!(initial.status, Status::Unknown);
        let ServiceDetails::FundingStatus(details) = initial.details else {
            panic!("expected funding details")
        };
        assert_eq!(details.url, url.as_str());
        assert!(details.status.is_none());

        for (http_status, body, expected) in [
            (StatusCode::OK, RESPONSE, Status::Healthy),
            (StatusCode::SERVICE_UNAVAILABLE, RESPONSE, Status::Unhealthy),
            (StatusCode::OK, "not json", Status::Unhealthy),
            (StatusCode::OK, "{}", Status::Unhealthy),
            (StatusCode::OK, RESPONSE, Status::Healthy),
        ] {
            tx.send_replace((http_status, body));
            let status = service.check().await;
            assert_eq!(status.status, expected);
            assert_eq!(status.error.is_none(), expected == Status::Healthy);
            let ServiceDetails::FundingStatus(details) = status.details else {
                panic!("expected funding details")
            };
            assert_eq!(details.url, url.as_str());
            if expected == Status::Healthy {
                let status = details.status.unwrap();
                assert_eq!(status.version, "1.2.3");
                assert_eq!(status.account_id, "0x1234");
                assert_eq!(status.native_asset.asset_id, "0xabcd");
                assert_eq!(status.native_asset.symbol, "MIDEN");
                assert_eq!(status.native_asset.decimals, 6);
                assert_eq!(status.native_asset.name, "Miden");
                assert_eq!(status.balance, 0);
                assert_eq!(status.chain_tip, 42);
                assert_eq!(status.max_amount, 1_000_000_000);
                assert_eq!(status.verification_base_fee, 7);
            } else {
                assert!(details.status.is_none());
            }
        }
        server.abort();
    }

    #[tokio::test]
    async fn slow_funding_endpoint_is_unhealthy() {
        let app = Router::new()
            .route("/status", get(|| async { std::future::pending::<&'static str>().await }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut service =
            FundingService::new(url, Duration::from_secs(1), Duration::from_millis(50));
        let status = tokio::time::timeout(Duration::from_secs(5), service.check()).await.unwrap();
        assert_eq!(status.status, Status::Unhealthy);
        assert!(status.error.is_some());
        server.abort();
    }
}
