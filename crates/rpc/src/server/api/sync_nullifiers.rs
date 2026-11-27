use miden_node_proto::{DecodeMessage, Verify, generated as proto};
use miden_node_store::DatabaseError;
use miden_node_tracing::{debug, instrument, miden_span_record};
use miden_node_utils::limiter::QueryParamNullifierPrefixLimit;

use super::error_codes::SyncNullifiersErrorCode;
use super::{
    RpcService,
    check,
    check_range_within_tip,
    database_error_to_status,
    invalid_block_range_to_status,
};

#[tonic::async_trait]
impl proto::server::miden_node_v1_node_service::SyncNullifiers for RpcService {
    type Input = proto::miden::node::v1::DecodedSyncNullifiersRequest;
    type Output = proto::miden::node::v1::SyncNullifiersResponse;

    fn decode(
        request: proto::miden::node::v1::SyncNullifiersRequest,
    ) -> tonic::Result<Self::Input> {
        check::<QueryParamNullifierPrefixLimit>(request.nullifiers.len())?;
        request
            .decode_fields()
            .map_err(|err| SyncNullifiersErrorCode::DeserializationFailed.invalid_argument(err))
    }

    fn encode(
        output: Self::Output,
    ) -> tonic::Result<proto::miden::node::v1::SyncNullifiersResponse> {
        Ok(output)
    }

    #[instrument(name = "sync_nullifiers")]
    async fn handle(
        &self,
        request: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        let range = request.block_range;
        let nullifiers = request.nullifiers.into_inner();

        miden_span_record!(
            block_range.from = range.block_from,
            block_range.to = range.block_to,
            prefix_len = request.prefix_len,
            prefixes = nullifiers.as_slice() #[nonstandard]
        );

        debug!(

            "Syncing nullifiers",
            block_range.from = range.block_from,
            block_range.to = range.block_to,
            prefix_len = request.prefix_len,
            prefixes = nullifiers.as_slice() #[nonstandard]
        );

        if request.prefix_len != 16 {
            return Err(SyncNullifiersErrorCode::InvalidPrefixLength.invalid_argument(format!(
                "unsupported prefix length: {} (only 16-bit prefixes are supported)",
                request.prefix_len
            )));
        }

        // Every prefix must fit in the requested 16-bit prefix length. Rejecting out-of-range
        // values keeps them from being truncated (e.g. 65536 -> 0) into a different prefix than the
        // client requested.
        let nullifier_prefixes = nullifiers
            .iter()
            .map(|&prefix| {
                u16::try_from(prefix).map_err(|_| {
                    SyncNullifiersErrorCode::DeserializationFailed.invalid_argument(format!(
                        "nullifier prefix {prefix} does not fit in the requested prefix length of 16 bits"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let block_range = range.verify().map_err(invalid_block_range_to_status)?;
        let block_to = *block_range.end();
        let (chain_tip, page) = self
            .state
            .read(move |view| {
                let chain_tip = view.snapshot.block_num;
                check_range_within_tip(&block_range, chain_tip)?;
                let page = view.tx.select_nullifiers_by_prefix(&nullifier_prefixes, block_range)?;
                Ok::<_, DatabaseError>((chain_tip, page))
            })
            .await
            .map_err(|err| match err {
                DatabaseError::RangeBeyondTip(_) => {
                    SyncNullifiersErrorCode::FutureBlock.invalid_argument(err)
                },
                err => database_error_to_status(&err),
            })?;
        let block_num = page.last_block_included(block_to);
        let nullifiers = page
            .items
            .into_iter()
            .map(|nullifier_info| {
                proto::miden::node::v1::sync_nullifiers_response::NullifierUpdate {
                    nullifier: Some(nullifier_info.nullifier.as_word().into()),
                    block_num: nullifier_info.block_num.as_u32(),
                }
            })
            .collect();

        Ok(proto::miden::node::v1::SyncNullifiersResponse {
            pagination_info: Some(proto::miden::node::v1::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: block_num.as_u32(),
            }),
            nullifiers,
        })
    }
}
