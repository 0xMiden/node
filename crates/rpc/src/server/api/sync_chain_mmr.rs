use miden_node_proto::generated as proto;
use miden_protocol::block::BlockNumber;
use tonic::Status;
use tracing::{debug, instrument};

use super::{Finality, RpcService};
use crate::{COMPONENT, LOG_TARGET};

#[tonic::async_trait]
impl proto::server::rpc_api::SyncChainMmr for RpcService {
    type Input = proto::rpc::SyncChainMmrRequest;
    type Output = proto::rpc::SyncChainMmrResponse;

    fn decode(request: proto::rpc::SyncChainMmrRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::SyncChainMmrResponse> {
        Ok(output)
    }

    #[instrument(
        target = COMPONENT,
        name = "sync_chain_mmr",
        skip_all,
        fields(
            current_client_block_height = %request.current_client_block_height,
            finality_level = %request.finality_level().as_str_name(),
        ),
        err,
    )]
    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::Output> {
        debug!(target: LOG_TARGET, "Syncing chain MMR");

        let current_client_block_height = BlockNumber::from(request.current_client_block_height);
        let sync_target = match request.finality_level() {
            proto::rpc::FinalityLevel::Committed | proto::rpc::FinalityLevel::Unspecified => {
                self.store.chain_tip(Finality::Committed).await
            },
            proto::rpc::FinalityLevel::Proven => self.store.chain_tip(Finality::Proven).await,
        };

        if current_client_block_height > sync_target {
            return Err(Status::invalid_argument(format!(
                "start block is not known: current client block height {current_client_block_height} is greater than chain tip {sync_target}"
            )));
        }

        let block_range = current_client_block_height..=sync_target;
        let (mmr_delta, block_header, block_signature) = self
            .store
            .sync_chain_mmr(block_range.clone())
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        Ok(proto::rpc::SyncChainMmrResponse {
            block_range: Some(proto::rpc::BlockRange {
                block_from: block_range.start().as_u32(),
                block_to: block_range.end().as_u32(),
            }),
            mmr_delta: Some(mmr_delta.into()),
            block_header: Some(block_header.into()),
            block_signature: Some(block_signature.into()),
        })
    }
}
