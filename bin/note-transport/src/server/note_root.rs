use miden_node_proto::errors::ConversionResultExt;
use miden_node_proto::generated::rpc::BlockHeaderByNumberRequest;
use miden_node_proto::{BuildUnchecked, DecodeMessage};
use miden_node_tracing::{error, miden_instrument, miden_span_record};
use miden_protocol::Word;
use miden_protocol::block::BlockNumber;

use super::Server;
use crate::{COMPONENT, LOG_TARGET};

impl Server {
    /// Returns the trusted node's note root for the requested block.
    #[miden_instrument(target = COMPONENT, err)]
    pub(super) async fn get_note_root(&self, block_num: BlockNumber) -> tonic::Result<Word> {
        miden_span_record!(block.number = block_num);
        if let Some(root) = self.note_root_cache.get(&block_num) {
            return Ok(root);
        }

        let mut rpc = self.rpc.clone();
        let response = tokio::time::timeout(
            // Reserve half of the request budget for note validation and storage.
            self.config.grpc.request_timeout / 2,
            rpc.get_block_header_by_number(BlockHeaderByNumberRequest {
                block_num: Some(block_num.as_u32()),
                include_mmr_proof: Some(false),
                include_protocol_config: Some(false),
            }),
        )
        .await
        .map_err(|_| tonic::Status::deadline_exceeded("block header lookup timed out"))?
        .map_err(|error| lookup_status(&error))?
        .into_inner();

        let header = response.block_header
            .ok_or_else(|| tonic::Status::failed_precondition("proof block is not available"))?
            .decode_fields()
            // The configured node supplies the canonical header. No parent check is required.
            .and_then(|header| header.build_unchecked().context("block_header"))
            .map_err(|error| {
                error!(error, target: LOG_TARGET, "Invalid node block header");
                tonic::Status::unavailable("node returned an invalid block header")
            })?;
        if header.block_num() != block_num {
            return Err(tonic::Status::unavailable("node returned a different block"));
        }

        let root = header.note_root();
        self.note_root_cache.put(block_num, root);
        Ok(root)
    }
}

fn lookup_status(error: &tonic::Status) -> tonic::Status {
    match error.code() {
        tonic::Code::NotFound => tonic::Status::failed_precondition("proof block is not available"),
        tonic::Code::DeadlineExceeded => {
            tonic::Status::deadline_exceeded("block header lookup timed out")
        },
        _ => {
            error!(error, target: LOG_TARGET, "Block header lookup failed");
            tonic::Status::unavailable("block header lookup failed")
        },
    }
}
