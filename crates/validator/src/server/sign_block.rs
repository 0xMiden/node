use miden_node_proto::generated as grpc;
use miden_node_utils::ErrorReport;
use miden_protocol::block::ProposedBlock;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::Signature;
use miden_tx::utils::{Deserializable, Serializable};

use crate::block_validation::validate_block;
use crate::server::ValidatorServer;

#[tonic::async_trait]
impl grpc::server::validator_api::SignBlock for ValidatorServer {
    type Input = ProposedBlock;
    type Output = Signature;

    fn decode(request: grpc::blockchain::ProposedBlock) -> tonic::Result<Self::Input> {
        ProposedBlock::read_from_bytes(&request.proposed_block)
            .map_err(|err| tonic::Status::invalid_argument(err.as_report()))
    }

    fn encode(output: Self::Output) -> tonic::Result<grpc::blockchain::BlockSignature> {
        Ok(grpc::blockchain::BlockSignature { signature: output.to_bytes() })
    }

    async fn handle(&self, input: Self::Input) -> tonic::Result<Self::Output> {
        let signature = validate_block(input, &self.signer, &self.db).await.map_err(|err| {
            tonic::Status::invalid_argument(format!(
                "Failed to validate block: {}",
                err.as_report()
            ))
        })?;
        Ok(signature)
    }
}
