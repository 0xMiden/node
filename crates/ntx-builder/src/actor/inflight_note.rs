use miden_node_proto::domain::note::SingleTargetNetworkNote;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Note;

use crate::actor::has_backoff_passed;

// INFLIGHT NETWORK NOTE
// ================================================================================================

/// An unconsumed network note that may have failed to execute.
///
/// The block number at which the network note was attempted are approximate and may not
/// reflect the exact block number for which the execution attempt failed. The actual block
/// will likely be soon after the number that is recorded here.
#[derive(Debug, Clone)]
pub struct InflightNetworkNote {
    note: SingleTargetNetworkNote,
    attempt_count: usize,
    last_attempt: Option<BlockNumber>,
}

impl InflightNetworkNote {
    /// Creates a new inflight network note.
    pub fn new(note: SingleTargetNetworkNote) -> Self {
        Self {
            note,
            attempt_count: 0,
            last_attempt: None,
        }
    }

    /// Consumes the inflight network note and returns the inner network note.
    pub fn into_inner(self) -> SingleTargetNetworkNote {
        self.note
    }

    /// Returns a reference to the inner network note.
    pub fn to_inner(&self) -> &SingleTargetNetworkNote {
        &self.note
    }

    /// Returns the number of attempts made to execute the network note.
    pub fn attempt_count(&self) -> usize {
        self.attempt_count
    }

    /// Checks if the network note is available for execution.
    ///
    /// The note is available if the backoff period has passed.
    pub fn is_available(&self, block_num: BlockNumber) -> bool {
        self.note.can_be_consumed(block_num).unwrap_or(true)
            && has_backoff_passed(block_num, self.last_attempt, self.attempt_count)
    }

    /// Registers a failed attempt to execute the network note at the specified block number.
    pub fn fail(&mut self, block_num: BlockNumber) {
        self.last_attempt = Some(block_num);
        self.attempt_count += 1;
    }
}

impl From<InflightNetworkNote> for Note {
    fn from(value: InflightNetworkNote) -> Self {
        value.into_inner().into()
    }
}
