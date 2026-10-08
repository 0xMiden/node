use miden_node_proto::errors::ConversionError;
use miden_node_proto::{DecodeMessageExt, generated as proto};
use miden_node_store::allowlist::InvitationCode;
use miden_node_tracing::{ErrorReport, miden_instrument};
use tonic::{Request, Status};

use super::{RpcBackend, RpcService};
use crate::COMPONENT;

#[tonic::async_trait]
impl proto::server::miden_node_v1_node_service::IsInvitationCodeValid for RpcService {
    type Input = String;
    type Output = bool;

    fn decode(
        request: proto::miden::node::v1::IsInvitationCodeValidRequest,
    ) -> tonic::Result<Self::Input> {
        request.decode_and_verify().map_err(ConversionError::into_status)
    }

    fn encode(
        valid: Self::Output,
    ) -> tonic::Result<proto::miden::node::v1::IsInvitationCodeValidResponse> {
        Ok(proto::miden::node::v1::IsInvitationCodeValidResponse { valid })
    }

    // The invitation code is a secret. Do not record it on the span.
    #[miden_instrument(target = COMPONENT, name = "is_invitation_code_valid", err)]
    async fn handle(
        &self,
        invitation_code: Self::Input,
        metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        match &self.backend {
            RpcBackend::Sequencer { account_admission, .. } => {
                if account_admission.is_disabled() {
                    return Ok(true);
                }
                let invitation = InvitationCode::new(&invitation_code)
                    .map_err(|error| Status::invalid_argument(error.to_string()))?;
                account_admission
                    .is_invitation_code_valid(invitation)
                    .await
                    .map_err(|error| Status::internal(error.as_report()))
            },
            RpcBackend::FullNode { source_rpc, .. } => {
                let mut request =
                    Request::new(proto::miden::node::v1::IsInvitationCodeValidRequest {
                        invitation_code,
                    });
                if let Some(accept) = metadata.get(http::header::ACCEPT.as_str()) {
                    request.metadata_mut().insert(http::header::ACCEPT.as_str(), accept.clone());
                }
                source_rpc
                    .as_ref()
                    .clone()
                    .is_invitation_code_valid(request)
                    .await
                    .map(|response| response.into_inner().valid)
            },
        }
    }
}
