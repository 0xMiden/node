//! Typed conversions at the boundary between the two public RPC services.
use crate::generated::miden::node::{v1, v2};

macro_rules! copy_fields {
    ($src:ident => $dst:ident, $name:ident { $($field:ident),* }) => {
        impl From<$src::$name> for $dst::$name {
            fn from(value: $src::$name) -> Self {
                let $src::$name { $($field),* } = value;
                Self { $($field),* }
            }
        }
    };
}

copy_fields!(v2 => v1, StatusRequest {  });
copy_fields!(v2 => v1, GetNetworkNoteStatusRequest { note_id });
copy_fields!(v2 => v1, GetBlockByNumberRequest { block_num, include_proof });
copy_fields!(v1 => v2, GetBlockByNumberResponse { block, proof });
copy_fields!(v2 => v1, GetBlockHeaderByNumberRequest { block_num, include_mmr_proof, include_protocol_config });
copy_fields!(v1 => v2, GetBlockHeaderByNumberResponse { block_header, mmr_path, chain_length, protocol_config });
copy_fields!(v2 => v1, GetNotesByIdRequest { note_ids });
copy_fields!(v2 => v1, GetNoteScriptByRootRequest { root });
copy_fields!(v1 => v2, GetNoteScriptByRootResponse { script });
copy_fields!(v2 => v1, GetTransactionEncryptionKeyRequest {  });
copy_fields!(v1 => v2, GetTransactionEncryptionKeyResponse { key });
copy_fields!(v2 => v1, SubmitProvenTxRequest { submission });
copy_fields!(v1 => v2, SubmitProvenTxResponse { block_num });
copy_fields!(v2 => v1, SubmitProvenTxBatchRequest { submission });
copy_fields!(v1 => v2, SubmitProvenTxBatchResponse { block_num });
copy_fields!(v2 => v1, BlockSubscriptionRequest { block_from });
copy_fields!(v1 => v2, BlockSubscriptionResponse { block, committed_chain_tip, protocol_config });
copy_fields!(v2 => v1, ProofSubscriptionRequest { block_from });
copy_fields!(v1 => v2, ProofSubscriptionResponse { block_num, proof, proven_chain_tip });
copy_fields!(v1 => v2, MempoolStats { unbatched_transactions, proposed_batches, proven_batches, uncommitted_transactions });
copy_fields!(v1 => v2, NetworkNoteSponsorship { note_id, fee_asset, reclaim_height, committed_block_num, last_error, last_attempt_block_num });
copy_fields!(v1 => v2, CommittedNote { note, inclusion_proof });

impl From<v1::StatusResponse> for v2::StatusResponse {
    fn from(value: v1::StatusResponse) -> Self {
        Self {
            version: value.version,
            genesis_commitment: value.genesis_commitment,
            chain_tip: value.chain_tip,
            block_producer: value.block_producer.map(Into::into),
        }
    }
}

impl From<v1::BlockProducerStatus> for v2::BlockProducerStatus {
    fn from(value: v1::BlockProducerStatus) -> Self {
        Self {
            version: value.version,
            status: value.status,
            chain_tip: value.chain_tip,
            mempool_stats: value.mempool_stats.map(Into::into),
        }
    }
}

impl From<v1::GetNotesByIdResponse> for v2::GetNotesByIdResponse {
    fn from(value: v1::GetNotesByIdResponse) -> Self {
        Self {
            notes: value.notes.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<v1::GetNetworkNoteStatusResponse> for v2::GetNetworkNoteStatusResponse {
    fn from(value: v1::GetNetworkNoteStatusResponse) -> Self {
        Self {
            status: value.status,
            last_error: value.last_error,
            attempt_count: value.attempt_count,
            last_attempt_block_num: value.last_attempt_block_num,
            sponsorships: value.sponsorships.into_iter().map(Into::into).collect(),
        }
    }
}
