//! In-memory validator configuration state carried through block commitment.

use miden_protocol::block::BlockNumber;
use tokio::sync::OwnedMutexGuard;

/// A quorum change scheduled to take effect at a specific block height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingValidatorQuorum {
    pub quorum: u16,
    /// The first block signed under the new quorum.
    pub activation_height: BlockNumber,
}

/// Holds the pending configuration until a block write finishes, even if its caller is cancelled.
pub type ValidatorConfigGuard = OwnedMutexGuard<Option<PendingValidatorQuorum>>;
