//! v2 entry points for methods with shared admission, validation, and backend behavior.
use miden_node_proto::generated::miden::node::v2;
use miden_node_proto::generated::server::{
    miden_node_v1_node_service as legacy,
    miden_node_v2_node_service as current,
};
use miden_node_tracing::instrument;

use super::RpcService;

macro_rules! unary {
    ($name:ident, $request:ident, $response:ident, $span:literal, $input:ident $(, $($fields:tt)+)?) => {
        #[tonic::async_trait]
        impl current::$name for RpcService {
            type Input = <Self as legacy::$name>::Input;
            type Output = <Self as legacy::$name>::Output;

            fn decode(request: v2::$request) -> tonic::Result<Self::Input> {
                <Self as legacy::$name>::decode(request.into())
            }
            fn encode(output: Self::Output) -> tonic::Result<v2::$response> {
                <Self as legacy::$name>::encode(output).map(Into::into)
            }
            #[instrument(name = $span $(, fields($($fields)+))?)]
            async fn handle(
                &self,
                $input: Self::Input,
                metadata: &tonic::metadata::MetadataMap,
                extensions: &tonic::codegen::http::Extensions,
            ) -> tonic::Result<Self::Output> {
                <Self as legacy::$name>::handle(self, $input, metadata, extensions).await
            }
        }
    };
}
unary!(Status, StatusRequest, StatusResponse, "status_v2", input);
unary!(
    GetNetworkNoteStatus,
    GetNetworkNoteStatusRequest,
    GetNetworkNoteStatusResponse,
    "get_network_note_status_v2",
    input,
    note.id = input
);
unary!(
    GetBlockByNumber,
    GetBlockByNumberRequest,
    GetBlockByNumberResponse,
    "get_block_by_number_v2",
    input,
    block.number = input.block_num,
    request.include_proof = input.include_proof
);
unary!(
    GetBlockHeaderByNumber,
    GetBlockHeaderByNumberRequest,
    GetBlockHeaderByNumberResponse,
    "get_block_header_by_number_v2",
    input,
    block.number = input.block_num,
    request.include_mmr_proof = input.include_mmr_proof,
    request.include_protocol_config = input.include_protocol_config
);
unary!(
    GetNotesById,
    GetNotesByIdRequest,
    GetNotesByIdResponse,
    "get_notes_by_id_v2",
    input,
    note.count = input.note_ids.as_slice().len()
);
unary!(
    GetNoteScriptByRoot,
    GetNoteScriptByRootRequest,
    GetNoteScriptByRootResponse,
    "get_note_script_by_root_v2",
    input,
    script.root = input
);
unary!(
    GetTransactionEncryptionKey,
    GetTransactionEncryptionKeyRequest,
    GetTransactionEncryptionKeyResponse,
    "get_transaction_encryption_key_v2",
    input
);
unary!(
    SubmitProvenTx,
    SubmitProvenTxRequest,
    SubmitProvenTxResponse,
    "submit_proven_tx_v2",
    input,
    transaction.id = input.transaction.id()
);
unary!(
    SubmitProvenTxBatch,
    SubmitProvenTxBatchRequest,
    SubmitProvenTxBatchResponse,
    "submit_proven_tx_batch_v2",
    input,
    batch.size = input.sealed_transaction_inputs.len()
);

macro_rules! stream {
    ($name:ident, $request:ident, $response:ident, $span:literal, $input:ident $(, $($fields:tt)+)?) => {
        #[tonic::async_trait]
        impl current::$name for RpcService {
            type Input = <Self as legacy::$name>::Input;
            type Item = <Self as legacy::$name>::Item;
            type ItemStream = <Self as legacy::$name>::ItemStream;

            fn decode(request: v2::$request) -> tonic::Result<Self::Input> {
                <Self as legacy::$name>::decode(request.into())
            }
            fn encode(output: Self::Item) -> tonic::Result<v2::$response> {
                <Self as legacy::$name>::encode(output).map(Into::into)
            }
            #[instrument(name = $span $(, fields($($fields)+))?)]
            async fn handle(
                &self,
                $input: Self::Input,
                metadata: &tonic::metadata::MetadataMap,
                extensions: &tonic::codegen::http::Extensions,
            ) -> tonic::Result<Self::ItemStream> {
                <Self as legacy::$name>::handle(self, $input, metadata, extensions).await
            }
        }
    };
}
stream!(
    BlockSubscription,
    BlockSubscriptionRequest,
    BlockSubscriptionResponse,
    "block_subscription_v2",
    input,
    block.from = input
);
stream!(
    ProofSubscription,
    ProofSubscriptionRequest,
    ProofSubscriptionResponse,
    "proof_subscription_v2",
    input,
    block.from = input
);
