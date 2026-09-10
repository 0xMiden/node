use miden_node_proto::generated as proto;
use miden_node_proto::server::funding_service_api;

use super::FundingRpcServer;
use crate::COMPONENT;
use crate::status::StatusSnapshot;

#[tonic::async_trait]
impl funding_service_api::Status for FundingRpcServer {
    type Input = ();
    type Output = StatusSnapshot;

    fn decode(_request: ()) -> tonic::Result<Self::Input> {
        Ok(())
    }

    #[miden_node_tracing::miden_instrument(target = COMPONENT, name = "status")]
    async fn handle(
        &self,
        (): Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        // The status is served while the service is still synchronizing, so an operator can read
        // the funding account it was configured with.
        Ok(self.status.clone())
    }

    fn encode(status: Self::Output) -> tonic::Result<proto::funding_service::FundingServiceStatus> {
        Ok(proto::funding_service::FundingServiceStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            account_id: Some(status.account_id().into()),
            balance: status.balance(),
            chain_tip: status.chain_tip().as_u32(),
            max_amount: status.max_amount(),
            verification_base_fee: status.verification_base_fee(),
        })
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::account::AccountId;
    use miden_protocol::asset::FungibleAsset;

    use super::*;
    use crate::server::tests::test_server;

    #[tokio::test]
    async fn status_reports_the_configured_account_and_the_published_balance() {
        let server = test_server(500);
        server.status.update(1_234, 42.into(), 7);

        let status = funding_service_api::Status::handle(
            &server,
            (),
            &tonic::metadata::MetadataMap::new(),
            &tonic::codegen::http::Extensions::new(),
        )
        .await
        .unwrap();
        let encoded = <FundingRpcServer as funding_service_api::Status>::encode(status).unwrap();

        assert_eq!(
            AccountId::try_from(encoded.account_id.unwrap()).unwrap(),
            FungibleAsset::mock_issuer()
        );
        assert_eq!(encoded.balance, 1_234);
        assert_eq!(encoded.chain_tip, 42);
        assert_eq!(encoded.max_amount, 500);
        assert_eq!(encoded.verification_base_fee, 7);
        assert_eq!(encoded.version, env!("CARGO_PKG_VERSION"));
    }

    /// The status must be available before the service is ready, so an operator can see which
    /// account it is waiting on.
    #[tokio::test]
    async fn status_is_served_while_the_service_is_not_ready() {
        let server = test_server(500);

        funding_service_api::Status::handle(
            &server,
            (),
            &tonic::metadata::MetadataMap::new(),
            &tonic::codegen::http::Extensions::new(),
        )
        .await
        .expect("status must not depend on readiness");
    }
}
