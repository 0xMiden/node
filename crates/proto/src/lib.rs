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

/// Bounded transport capacity for blocks, including logs and protobuf overhead.
pub const MAX_BLOCK_MESSAGE_SIZE: usize = 64 * 1024 * 1024;
