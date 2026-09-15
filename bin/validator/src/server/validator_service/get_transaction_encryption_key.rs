use miden_node_proto::generated as grpc;
use miden_node_tracing::miden_instrument;

use super::ValidatorService;
use crate::COMPONENT;

#[tonic::async_trait]
impl grpc::server::validator_api::GetTransactionEncryptionKey for ValidatorService {
    type Input = ();
    type Output = grpc::submission::TransactionEncryptionKey;

    fn decode(request: ()) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<grpc::submission::TransactionEncryptionKey> {
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
        Ok(grpc::submission::TransactionEncryptionKey {
            scheme: self.encryption_key_info.scheme.as_i32(),
            key_id: self.encryption_key_info.key_id.clone(),
            public_key: self.encryption_key_info.public_key.clone(),
            attestations: vec![grpc::submission::ValidatorKeyAttestation {
                validator_public_key: Some((&self.signer.public_key()).into()),
                signature: Some((&self.encryption_key_attestation).into()),
            }],
            next_key: self.encryption_key_info.next_key.as_ref().map(|next| {
                grpc::submission::NextTransactionEncryptionKey {
                    scheme: next.scheme.as_i32(),
                    key_id: next.key_id.clone(),
                    public_key: next.public_key.clone(),
                    rotation_block_num: next.rotation_block_num,
                }
            }),
        })
    }
}
