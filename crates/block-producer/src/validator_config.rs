//! Validator configuration registration for a running sequencer.

use std::sync::Arc;

use miden_node_store::State;
pub use miden_node_store::validator_config::PendingValidatorQuorum;
use tokio::sync::Mutex;

/// The chain state and an in-memory schedule for changing its validator configuration.
///
/// The pending change is locked while building and committing blocks. A new sequencer starts with
/// no pending change; committed configuration is read from the chain tip.
#[derive(Clone)]
pub struct ValidatorConfigState {
    pub state: Arc<State>,
    pub pending: Arc<Mutex<Option<PendingValidatorQuorum>>>,
}

impl ValidatorConfigState {
    /// Starts a registration state with no pending change.
    pub fn new(state: Arc<State>) -> Self {
        Self { state, pending: Arc::default() }
    }
}
