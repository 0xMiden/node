use miden_node_proto::generated as proto;
use miden_node_store::StateSyncError;
use miden_node_tracing::{debug, instrument};
use miden_protocol::block::BlockNumber;
use proto::miden::node::{v1, v2};

use super::RpcService;
use super::error_codes::{SyncChainMmrErrorCode, internal_error, log_internal_error};

#[tonic::async_trait]
impl proto::server::miden_node_v1_node_service::SyncChainMmr for RpcService {
    type Input = proto::miden::node::v1::SyncChainMmrRequest;
    type Output = proto::miden::node::v1::SyncChainMmrResponse;

    fn decode(request: proto::miden::node::v1::SyncChainMmrRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::miden::node::v1::SyncChainMmrResponse> {
        Ok(output)
    }

    #[instrument(
        name = "sync_chain_mmr",
        fields(
            current_client_block_height = request.current_client_block_height,
            finality_level = request.finality_level()
        ),
    )]
    async fn handle(
        &self,
        request: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        debug!("Syncing chain MMR");

        let current_client_block_height = BlockNumber::from(request.current_client_block_height);

        // Read the target tip before creating the view: tips are monotonic and each committed tip
        // is published after its snapshot, so the view below is guaranteed to be able to serve
        // `sync_target`.
        let sync_target = match request.finality_level() {
            proto::miden::node::v1::FinalityLevel::Committed
            | proto::miden::node::v1::FinalityLevel::Unspecified => self.state.committed_tip(),
            proto::miden::node::v1::FinalityLevel::Proven => self.state.proven_tip(),
        };

        self.chain_mmr_at(current_client_block_height, sync_target).await
    }
}

#[tonic::async_trait]
impl proto::server::miden_node_v2_node_service::SyncChainMmr for RpcService {
    type Input = v2::SyncChainMmrRequest;
    type Output = v1::SyncChainMmrResponse;

    fn decode(request: v2::SyncChainMmrRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<v2::SyncChainMmrResponse> {
        Ok(v2::SyncChainMmrResponse {
            block_range: output.block_range.map(|range| v2::BlockRange {
                block_from: range.block_from,
                block_to: range.block_to,
            }),
            mmr_delta: output.mmr_delta,
            block_header: output.block_header,
            block_signatures: output.block_signatures,
            protocol_config: output.protocol_config,
        })
    }

    #[instrument(
        name = "sync_chain_mmr_v2",
        fields(
            current_client_block_height = request.current_client_block_height,
            block_range.to = request.target_block_num,
            finality_level = v2::FinalityLevel::try_from(request.finality_level).ok(),
        ),
        err
    )]
    async fn handle(
        &self,
        request: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        let finality = v2::FinalityLevel::try_from(request.finality_level)
            .map_err(|_| tonic::Status::invalid_argument("unknown finality level"))?;
        let ceiling = match finality {
            v2::FinalityLevel::Proven => self.state.proven_tip(),
            v2::FinalityLevel::Unspecified | v2::FinalityLevel::Committed => {
                self.state.committed_tip()
            },
        };
        let target = request.target_block_num.map_or(ceiling, BlockNumber::from);
        if target > ceiling {
            return Err(tonic::Status::out_of_range(format!(
                "target block {target} exceeds selected tip {ceiling}"
            )));
        }
        self.chain_mmr_at(request.current_client_block_height.into(), target).await
    }
}

impl RpcService {
    async fn chain_mmr_at(
        &self,
        current_client_block_height: BlockNumber,
        sync_target: BlockNumber,
    ) -> tonic::Result<v1::SyncChainMmrResponse> {
        if current_client_block_height > sync_target {
            return Err(SyncChainMmrErrorCode::FutureBlock.invalid_argument(format!(
                "start block is not known: current client block height {current_client_block_height} is greater than chain tip {sync_target}"
            )));
        }

        let block_range = current_client_block_height..=sync_target;
        let view = self.state.view();
        let (mmr_delta, block_header, block_signatures) =
            view.sync_chain_mmr(block_range.clone()).await.map_err(|err| match err {
                StateSyncError::RangeBeyondTip(_) => {
                    SyncChainMmrErrorCode::FutureBlock.invalid_argument(err)
                },
                _ => log_internal_error(&err),
            })?;

        let protocol_config_required = if current_client_block_height == BlockNumber::GENESIS {
            true
        } else if current_client_block_height == sync_target {
            false
        } else {
            let commitment_at_start = view
                .get_protocol_config_commitment_at(current_client_block_height)
                .await
                .map_err(|err| log_internal_error(&err))?;
            let commitment_at_start = commitment_at_start.ok_or_else(|| {
                internal_error("starting protocol configuration activation is missing")
            })?;
            commitment_at_start != block_header.protocol_config_commitment()
        };

        let protocol_config = if protocol_config_required {
            Some(super::load_protocol_config(&view, &block_header).await?.into())
        } else {
            None
        };

        Ok(proto::miden::node::v1::SyncChainMmrResponse {
            protocol_config,
            block_range: Some(proto::miden::node::v1::BlockRange {
                block_from: block_range.start().as_u32(),
                block_to: block_range.end().as_u32(),
            }),
            mmr_delta: Some(mmr_delta.into()),
            block_header: Some(block_header.into()),
            block_signatures: block_signatures.as_signatures().iter().map(Into::into).collect(),
        })
    }
}
