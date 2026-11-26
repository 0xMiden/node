use miden_node_proto::generated as proto;
use miden_node_store::{DatabaseError, RangeBeyondTip, StateSyncError};
use miden_node_tracing::{debug, instrument};
use miden_protocol::block::{BlockNumber, Blockchain};
use miden_protocol::crypto::merkle::mmr::{Forest, MmrDelta, MmrError};
use proto::miden::node::{v1, v2};

use super::RpcService;
use super::error_codes::{SyncChainMmrErrorCode, log_internal_error};

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

        // Read the target tip before acquiring the view: tips are monotonic and each committed tip
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

        let (mmr_delta, block_header, block_signatures, protocol_config) = self
            .state
            .read(move |view| {
                let chain_tip = view.snapshot.block_num;
                if sync_target > chain_tip {
                    return Err(RangeBeyondTip { chain_tip, block_to: sync_target }.into());
                }
                let (block_header, block_signatures) =
                    view.tx.select_block_header_and_signatures(sync_target)?.expect(
                        "the sync target is at or below the chain tip, so its header is stored",
                    );
                let mmr_delta =
                    mmr_delta(view.snapshot.blockchain, current_client_block_height, sync_target)?;

                // Clients syncing from genesis need the configuration. Other clients need it only
                // if it changed within the range.
                let commitment = block_header.protocol_config_commitment();
                let protocol_config_required =
                    if current_client_block_height == BlockNumber::GENESIS {
                        true
                    } else if current_client_block_height == sync_target {
                        false
                    } else {
                        let commitment_at_start = view
                            .tx
                            .select_protocol_config_commitment_at(current_client_block_height)?
                            .ok_or_else(|| {
                                DatabaseError::DataCorrupted(
                                    "starting protocol configuration activation is missing".into(),
                                )
                            })?;
                        commitment_at_start != commitment
                    };
                let protocol_config = if protocol_config_required {
                    let config = view
                        .tx
                        .select_protocol_config(commitment)?
                        .ok_or(DatabaseError::ProtocolConfigNotFound(commitment))?;
                    Some(config)
                } else {
                    None
                };

                Ok::<_, StateSyncError>((
                    mmr_delta,
                    block_header,
                    block_signatures,
                    protocol_config,
                ))
            })
            .await
            .map_err(|err| match err {
                StateSyncError::RangeBeyondTip(_) => {
                    SyncChainMmrErrorCode::FutureBlock.invalid_argument(err)
                },
                StateSyncError::DatabaseError(err) => super::database_error_to_status(&err),
                _ => log_internal_error(&err),
            })?;

        Ok(proto::miden::node::v1::SyncChainMmrResponse {
            protocol_config: protocol_config.map(Into::into),
            block_range: Some(proto::miden::node::v1::BlockRange {
                block_from: current_client_block_height.as_u32(),
                block_to: sync_target.as_u32(),
            }),
            mmr_delta: Some(mmr_delta.into()),
            block_header: Some(block_header.into()),
            block_signatures: block_signatures.as_signatures().iter().map(Into::into).collect(),
        })
    }
}

/// Returns the MMR delta that advances a client's chain MMR from `block_from` to `block_to`.
///
/// The MMR forest is 1-indexed whereas block numbers are 0-indexed, and each header's MMR root
/// lags one block behind because MMR leaves are header commitments. These offsets cancel out.
/// `block_from` is the last block the client already has, so the delta starts at the next leaf.
fn mmr_delta(
    blockchain: &Blockchain,
    block_from: BlockNumber,
    block_to: BlockNumber,
) -> Result<MmrDelta, MmrError> {
    if block_from == block_to {
        let forest = Forest::new(block_from.as_usize()).expect("block index fits in u32");
        return Ok(MmrDelta { forest, data: vec![] });
    }
    let from_forest = Forest::new((block_from + 1).as_usize()).expect("from_forest fits in u32");
    let to_forest = Forest::new(block_to.as_usize()).expect("to_forest fits in u32");
    blockchain.as_mmr().get_delta(from_forest, to_forest)
}
