use miden_node_proto::decode::{read_account_ids, read_block_range};
use miden_node_proto::generated as proto;
use miden_node_store::{NoteSyncRecord, TransactionRecord};
use miden_node_utils::limiter::QueryParamAccountIdLimit;
use miden_protocol::asset::Asset;
use tonic::Status;
use tracing::debug;

use super::{
    RpcInvalidBlockRange,
    RpcService,
    check,
    database_error_to_status,
    invalid_block_range_to_status,
};
use crate::{COMPONENT, LOG_TARGET};

#[tonic::async_trait]
impl proto::server::rpc_api::SyncTransactions for RpcService {
    type Input = proto::rpc::SyncTransactionsRequest;
    type Output = proto::rpc::SyncTransactionsResponse;

    fn decode(request: proto::rpc::SyncTransactionsRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::SyncTransactionsResponse> {
        Ok(output)
    }

    #[miden_node_utils::tracing::miden_instrument(
        target = COMPONENT,
        name = "sync_transactions",
        skip_all,
        err,
    )]
    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::Output> {
        tracing::trace!(target: LOG_TARGET, ?request);

        let range = read_block_range::<Status>(request.block_range, "SyncTransactionsRequest")?;
        let n_accounts = request.account_ids.len();
        let account_ids =
            read_account_ids::<Status, _>(request.account_ids.iter().take(10).cloned())?;

        miden_node_utils::tracing::miden_span_record!(
            block_range.from = range.block_from,
            block_range.to = range.block_to,
            account.ids = ?account_ids,
            account.ids.count = n_accounts,
        );

        debug!(target: LOG_TARGET, "Syncing transactions");

        check::<QueryParamAccountIdLimit>(request.account_ids.len())?;

        let block_range = range
            .into_inclusive_range::<RpcInvalidBlockRange>()
            .map_err(invalid_block_range_to_status)?;
        let chain_tip = self.range_bounds_check(&block_range).await?;
        let account_ids = read_account_ids::<Status, _>(request.account_ids)?;
        let (last_block_included, transaction_records_db) = self
            .store
            .sync_transactions(account_ids, block_range)
            .await
            .map_err(|err| database_error_to_status(&err))?;
        let transactions =
            transaction_records_db.into_iter().map(transaction_record_to_proto).collect();

        Ok(proto::rpc::SyncTransactionsResponse {
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: last_block_included.as_u32(),
            }),
            transactions,
        })
    }
}

// HELPERS
// ================================================================================================

fn transaction_record_to_proto(record: TransactionRecord) -> proto::rpc::TransactionRecord {
    let output_note_proofs = record
        .output_note_proofs
        .into_iter()
        .map(note_sync_record_to_proof_proto)
        .collect();

    proto::rpc::TransactionRecord {
        header: Some(proto::transaction::TransactionHeader {
            transaction_id: Some(record.header.id().into()),
            account_id: Some(record.header.account_id().into()),
            initial_state_commitment: Some(record.header.initial_state_commitment().into()),
            final_state_commitment: Some(record.header.final_state_commitment().into()),
            input_notes: record.header.input_notes().iter().cloned().map(Into::into).collect(),
            output_notes: record.header.output_notes().iter().copied().map(Into::into).collect(),
            fee: Some(Asset::from(record.header.fee()).into()),
        }),
        block_num: record.block_num.as_u32(),
        output_note_proofs,
    }
}

fn note_sync_record_to_proof_proto(note: NoteSyncRecord) -> proto::note::NoteInclusionInBlockProof {
    proto::note::NoteInclusionInBlockProof {
        note_id: Some((&note.note_id).into()),
        block_num: note.block_num.as_u32(),
        note_index_in_block: note.note_index.leaf_index_value().into(),
        inclusion_path: Some(note.inclusion_path.into()),
    }
}
