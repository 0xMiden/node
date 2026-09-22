use miden_node_proto::errors::ConversionError;
use miden_node_proto::{DecodeMessage, Verify, generated as proto};
use miden_node_store::{NoteSyncRecord, TransactionRecord};
use miden_node_tracing::{debug, miden_instrument, miden_span_record};
use miden_node_utils::limiter::QueryParamAccountIdLimit;

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
    type Input = proto::rpc::DecodedSyncTransactionsRequest;
    type Output = proto::rpc::SyncTransactionsResponse;

    fn decode(request: proto::rpc::SyncTransactionsRequest) -> tonic::Result<Self::Input> {
        check::<QueryParamAccountIdLimit>(request.account_ids.as_slice().len())?;
        request.decode_fields().map_err(ConversionError::into_status)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::SyncTransactionsResponse> {
        Ok(output)
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "sync_transactions",
        err,
    )]
    async fn handle(
        &self,
        request: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        let range = request.block_range;
        let n_accounts = request.account_ids.as_slice().len();
        let account_ids = request.account_ids.verify().map_err(ConversionError::into_status)?;
        let logged_account_ids = &account_ids[..account_ids.len().min(10)];

        miden_span_record!(
            block_range.from = range.block_from,
            block_range.to = range.block_to,
            account.ids = logged_account_ids,
            account.count = n_accounts
        );

        debug!(
            target: LOG_TARGET,
            "Syncing transactions",
            block_range.from = range.block_from,
            block_range.to = range.block_to,
            account.ids = logged_account_ids,
            account.ids.count = n_accounts
        );

        let block_range = range
            .verify()
            .map_err(RpcInvalidBlockRange::from)
            .map_err(invalid_block_range_to_status)?;
        let (chain_tip, (last_block_included, transaction_records_db)) = self
            .state
            .with_view(async |view| {
                view.sync_transactions(account_ids, block_range)
                    .await
                    .map(|records| (view.tip(), records))
                    .map_err(|err| database_error_to_status(&err))
            })
            .await?;
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

    let consumed_note_refs = record
        .consumed_note_refs
        .into_iter()
        .map(|(nullifier, note_id)| proto::rpc::ConsumedNoteRef {
            nullifier: Some(nullifier.as_word().into()),
            note_id: Some((&note_id).into()),
        })
        .collect();

    proto::rpc::TransactionRecord {
        header: Some(proto::transaction::TransactionHeader {
            transaction_id: Some(record.header.id().into()),
            account_id: Some(record.header.account_id().into()),
            initial_state_commitment: Some(record.header.initial_state_commitment().into()),
            final_state_commitment: Some(record.header.final_state_commitment().into()),
            input_notes: record.header.input_notes().iter().cloned().map(Into::into).collect(),
            output_notes: record.header.output_notes().iter().copied().map(Into::into).collect(),
        }),
        block_num: record.block_num.as_u32(),
        output_note_proofs,
        consumed_note_refs,
    }
}

fn note_sync_record_to_proof_proto(note: NoteSyncRecord) -> proto::note::NoteInclusionProof {
    proto::note::NoteInclusionProof {
        note_id: Some((&note.note_id).into()),
        block_num: Some(note.block_num.into()),
        note_index_in_block: note.note_index.leaf_index_value().into(),
        inclusion_path: Some(note.inclusion_path.into()),
    }
}
