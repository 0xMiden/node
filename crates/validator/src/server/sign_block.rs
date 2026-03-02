use miden_node_proto::generated as grpc;
use miden_node_proto::generated::server::validator_api::SignBlock;
use miden_node_proto::server::{GrpcDecode, GrpcEncode};
use miden_node_utils::ErrorReport;
use miden_protocol::block::ProposedBlock;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::Signature;
use miden_tx::utils::{Deserializable, Serializable};

use crate::block_validation::validate_block;
use crate::server::ValidatorServer;

#[tonic::async_trait]
impl miden_node_proto::server::GrpcUnary<SignBlock> for ValidatorServer {
    type Input = Input;
    type Output = Output;

    async fn handle(&self, input: Self::Input) -> tonic::Result<Self::Output> {
        let signature = validate_block(input.0, &self.signer, &self.db).await.map_err(|err| {
            tonic::Status::invalid_argument(format!(
                "Failed to validate block: {}",
                err.as_report()
            ))
        })?;
        Ok(Output(signature))
    }
}

pub struct Input(ProposedBlock);
pub struct Output(Signature);

impl GrpcEncode<grpc::blockchain::BlockSignature> for Output {
    fn encode(self) -> Result<grpc::blockchain::BlockSignature, tonic::Status> {
        Ok(grpc::blockchain::BlockSignature { signature: self.0.to_bytes() })
    }
}

impl GrpcDecode<grpc::blockchain::ProposedBlock> for Input {
    type Error = miden_protocol::utils::DeserializationError;

    fn decode(input: grpc::blockchain::ProposedBlock) -> Result<Self, Self::Error> {
        ProposedBlock::read_from_bytes(&input.proposed_block).map(Self)
    }
}
