// VALIDATOR STATUS CHECKER
// ================================================================================================

use std::time::Duration;

use miden_node_proto::clients::ValidatorClient;
use miden_node_utils::tracing::miden_instrument;
use url::Url;

use crate::COMPONENT;
use crate::service::{Service, build_tls_client};
use crate::status::{ServiceDetails, ServiceStatus, ValidatorStatusDetails};

pub struct ValidatorService {
    url: Url,
    client: ValidatorClient,
    interval: Duration,
}

impl ValidatorService {
    pub fn new(url: Url, interval: Duration, timeout: Duration) -> Self {
        let client = build_tls_client::<ValidatorClient>(url.clone(), timeout);
        Self { url, client, interval }
    }
}

impl Service for ValidatorService {
    fn name(&self) -> &'static str {
        "Validator"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn initial_status(&self) -> ServiceStatus {
        ServiceStatus::unknown(
            self.name(),
            ServiceDetails::ValidatorStatus(ValidatorStatusDetails::default()),
        )
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "check-status.validator",
        skip_all,
        ret(level = "info"),
    )]
    async fn check(&mut self) -> ServiceStatus {
        match self.client.status(()).await {
            Ok(response) => {
                let status = response.into_inner();
                ServiceStatus::healthy(
                    self.name(),
                    ServiceDetails::ValidatorStatus(ValidatorStatusDetails {
                        url: self.url.to_string(),
                        version: status.version,
                        chain_tip: status.chain_tip,
                        validated_transactions_count: status.validated_transactions_count,
                        signed_blocks_count: status.signed_blocks_count,
                    }),
                )
            },
            Err(e) => ServiceStatus::error(self.name(), e),
        }
    }
}
