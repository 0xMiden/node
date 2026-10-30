use miden_protocol::block::{BlockNumber, Blockchain};

/// Immutable chain state at the block selected when a read is acquired.
///
/// The blockchain includes the selected block. Its native MMR operations allow callers to construct
/// proofs without exposing endpoint-specific operations on the view.
pub struct StateSnapshot<'a> {
    pub block_num: BlockNumber,
    pub blockchain: &'a Blockchain,
}
