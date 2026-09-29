use miden_node_proto::generated as proto;
use miden_node_tracing::{debug, miden_instrument};

use super::{Request, RpcBackend, RpcService};
use crate::{COMPONENT, LOG_TARGET};

#[tonic::async_trait]
impl proto::server::miden_node_v1_node_service::GetTransactionEncryptionKey for RpcService {
    type Input = ();
    type Output = proto::submission::TransactionEncryptionKey;

    fn decode(
        _request: proto::miden::node::v1::GetTransactionEncryptionKeyRequest,
    ) -> tonic::Result<Self::Input> {
        Ok(())
    }

    fn encode(
        output: Self::Output,
    ) -> tonic::Result<proto::miden::node::v1::GetTransactionEncryptionKeyResponse> {
        Ok(proto::miden::node::v1::GetTransactionEncryptionKeyResponse { key: Some(output) })
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "get_transaction_encryption_key",
        err,
    )]
    async fn handle(
        &self,
        _input: Self::Input,
        metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        let original_accept_header = metadata.get(http::header::ACCEPT.as_str()).cloned();

        debug!(target: LOG_TARGET, "Getting transaction encryption key");

        let mut forwarded_request = Request::new(());
        if let Some(accept) = original_accept_header {
            forwarded_request.metadata_mut().insert(http::header::ACCEPT.as_str(), accept);
        }

        // Nodes connected to validators ask one directly, otherwise the request is forwarded. The
        // encryption key is shared by the whole validator set, so any single validator serves.
        let validator = match &self.backend {
            RpcBackend::Sequencer { validators, .. } => validators.random(),
            RpcBackend::FullNode { pre_auth: Some(pre_auth), .. } => pre_auth.validators().random(),
            RpcBackend::FullNode { source_rpc, pre_auth: None, .. } => {
                return source_rpc
                    .as_ref()
                    .clone()
                    .get_transaction_encryption_key(
                        forwarded_request.map(|()| {
                            proto::miden::node::v1::GetTransactionEncryptionKeyRequest {}
                        }),
                    )
                    .await
                    .and_then(|response| {
                        response.into_inner().key.ok_or_else(|| {
                            tonic::Status::internal("missing transaction encryption key")
                        })
                    });
            },
        };
        validator
            .clone()
            .get_transaction_encryption_key(
                forwarded_request
                    .map(|()| proto::miden::validator::v1::GetTransactionEncryptionKeyRequest {}),
            )
            .await
            .and_then(|response| {
                response
                    .into_inner()
                    .key
                    .ok_or_else(|| tonic::Status::internal("missing transaction encryption key"))
            })
    }
}
