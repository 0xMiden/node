use miden_node_proto::generated as grpc;
use miden_node_utils::tracing::miden_instrument;
use miden_tx::utils::serde::Serializable;

use super::ValidatorService;
use crate::COMPONENT;

#[tonic::async_trait]
impl grpc::server::validator_api::GetTransactionEncryptionKey for ValidatorService {
    type Input = ();
    type Output = grpc::transaction::TransactionEncryptionKey;

    fn decode(request: ()) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<grpc::transaction::TransactionEncryptionKey> {
        Ok(output)
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "get_transaction_encryption_key",
        err,
    )]
    async fn handle(
        &self,
        _input: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        // Built entirely from state fixed at construction, so the endpoint stays available while a
        // backup subscription holds the serve lock.
        Ok(grpc::transaction::TransactionEncryptionKey {
            scheme: self.encryption_key_info.scheme.as_i32(),
            key_id: self.encryption_key_info.key_id.clone(),
            public_key: self.encryption_key_info.public_key.clone(),
            attestations: vec![grpc::transaction::ValidatorKeyAttestation {
                validator_public_key: self.signer.public_key().to_bytes(),
                signature: self.encryption_key_attestation.to_bytes(),
            }],
            next_key: self.encryption_key_info.next_key.as_ref().map(|next| {
                grpc::transaction::NextTransactionEncryptionKey {
                    scheme: next.scheme.as_i32(),
                    key_id: next.key_id.clone(),
                    public_key: next.public_key.clone(),
                    rotation_block_num: next.rotation_block_num,
                }
            }),
        })
    }
}
