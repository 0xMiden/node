use miden_node_proto::generated as proto;
use miden_node_tracing::{ErrorReport, miden_instrument, miden_span_record};
use miden_protocol::account::AccountId;
use tonic::{Request, Status};

use super::{RpcBackend, RpcService};
use crate::COMPONENT;

#[tonic::async_trait]
impl proto::server::rpc_api::IsAccountAllowed for RpcService {
    type Input = AccountId;
    type Output = bool;

    fn decode(request: proto::account::AccountId) -> tonic::Result<Self::Input> {
        request.try_into().map_err(|_| Status::invalid_argument("invalid account_id"))
    }

    fn encode(allowed: Self::Output) -> tonic::Result<proto::rpc::IsAccountAllowedResponse> {
        Ok(proto::rpc::IsAccountAllowedResponse { allowed })
    }

    #[miden_instrument(target = COMPONENT, name = "is_account_allowed", err)]
    async fn handle(
        &self,
        account_id: Self::Input,
        metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        miden_span_record!(account.id = account_id);

        match &self.backend {
            RpcBackend::Sequencer { account_admission, .. } => account_admission
                .is_account_allowed(account_id)
                .await
                .map_err(|error| Status::internal(error.as_report())),
            RpcBackend::FullNode { source_rpc, .. } => {
                let mut request = Request::new(account_id.into());
                if let Some(accept) = metadata.get(http::header::ACCEPT.as_str()) {
                    request.metadata_mut().insert(http::header::ACCEPT.as_str(), accept.clone());
                }
                source_rpc
                    .as_ref()
                    .clone()
                    .is_account_allowed(request)
                    .await
                    .map(|response| response.into_inner().allowed)
            },
        }
    }
}
