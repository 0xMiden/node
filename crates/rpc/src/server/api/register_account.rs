use miden_node_proto::generated as proto;
use miden_node_store::allowlist::{AllowlistError, InvitationCode};
use miden_node_tracing::{ErrorReport, miden_instrument, miden_span_record};
use miden_protocol::account::AccountId;
use tonic::{Code, Request, Status};

use super::{RpcBackend, RpcService};
use crate::COMPONENT;

#[tonic::async_trait]
impl proto::server::rpc_api::RegisterAccount for RpcService {
    type Input = proto::rpc::RegisterAccountRequest;
    type Output = ();

    fn decode(request: proto::rpc::RegisterAccountRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode((): Self::Output) -> tonic::Result<()> {
        Ok(())
    }

    #[miden_instrument(target = COMPONENT, name = "register_account", err)]
    async fn handle(
        &self,
        request: Self::Input,
        metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        let account_id: AccountId = request
            .account_id
            .clone()
            .ok_or_else(|| Status::invalid_argument("missing account_id"))?
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid account_id"))?;
        miden_span_record!(account.id = account_id);

        let invitation = InvitationCode::new(&request.invitation_code)
            .map_err(|error| Status::invalid_argument(error.to_string()))?;

        match &self.backend {
            RpcBackend::Sequencer { allowlist, .. } => {
                allowlist.register_account(invitation, account_id).await.map(|_| ()).map_err(
                    |error| {
                        let code = match &error {
                            AllowlistError::InvitationNotFound => Code::NotFound,
                            AllowlistError::InvitationAlreadyUsed
                            | AllowlistError::AccountAlreadyRegistered(_) => Code::AlreadyExists,
                            AllowlistError::Database(_) => Code::Internal,
                        };
                        Status::new(code, error.as_report())
                    },
                )
            },
            RpcBackend::FullNode { source_rpc, .. } => {
                let mut request = Request::new(request);
                if let Some(accept) = metadata.get(http::header::ACCEPT.as_str()) {
                    request.metadata_mut().insert(http::header::ACCEPT.as_str(), accept.clone());
                }
                source_rpc.as_ref().clone().register_account(request).await.map(|_| ())
            },
        }
    }
}
