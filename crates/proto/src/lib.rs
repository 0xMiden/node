miden_node_tracing::declare_targets! {
    default: "miden::proto",
    "miden_node_proto::clients" => "miden::rpc::client",
    #[cfg(test)]
    "miden_node_proto::clients::tests::tracing_targets" => "miden::test::caller",
}

pub mod clients;

pub mod domain;
pub mod errors;

#[rustfmt::skip]
pub mod generated;

// RE-EXPORTS
// ================================================================================================

pub use domain::proof_request::BlockProofRequest;
pub use domain::sign_block_request::SignBlockRequest;
pub use domain::submission::{ProvenTransactionSubmission, TransactionBatchSubmission};
pub use generated::server;
pub use miden_protobuf::{
    BuildUnchecked,
    DecodeMessage,
    DecodeMessageExt,
    Decoded,
    Verify,
    VerifyWith,
};
pub use prost;
