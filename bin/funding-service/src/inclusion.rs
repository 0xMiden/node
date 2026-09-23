//! Waiting for a funding transaction to commit.

use std::time::Duration;

use miden_node_tracing::warn;
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;

use crate::LOG_TARGET;
use crate::node::RpcNodeClient;

// AWAIT INCLUSION
// ================================================================================================

/// The state change which a funding transaction applies to the funding account.
#[derive(Debug, Clone, Copy)]
pub struct AccountTransition {
    pub account_id: AccountId,
    /// The account state commitment which the transaction starts from.
    pub initial: Word,
    /// The account state commitment which the transaction produces.
    pub final_: Word,
    /// The last block which can include the transaction.
    pub expiration: BlockNumber,
}

/// The outcome of waiting for a funding transaction to commit.
#[derive(Debug, PartialEq, Eq)]
pub enum Inclusion {
    /// The funding account is at the state which the transaction produces.
    Committed,
    /// The transaction expired without committing, so no note was created.
    Expired,
    /// The funding account is at a state which neither precedes nor follows the transaction.
    Diverged { observed: Word, block: BlockNumber },
    /// The service is shutting down and stopped waiting.
    ShuttingDown,
}

/// Polls the node until the funding account shows that the transaction committed or expired.
///
/// The funding notes cannot show this. A requester which does not wait for the commit can consume
/// its note as an unauthenticated input in the same block which creates it. The block then erases
/// the note, and the node never returns it.
///
/// The loop ends: the chain tip only moves forward, so the answer is at the latest `Expired` once
/// the tip passes the expiration block.
pub async fn await_inclusion(
    node: &RpcNodeClient,
    transition: AccountTransition,
    poll_interval: Duration,
    shutdown: &CancellationToken,
) -> Inclusion {
    loop {
        match node.committed_account_commitment(transition.account_id).await {
            Ok((observed, block)) => {
                if let Some(inclusion) = classify(&transition, observed, block) {
                    return inclusion;
                }
            },
            Err(err) => {
                warn!(
                    &err,
                    target: LOG_TARGET,
                    "Failed to read the funding account while waiting for the transaction; retrying"
                );
            },
        }

        tokio::select! {
            () = tokio::time::sleep(poll_interval) => {},
            () = shutdown.cancelled() => return Inclusion::ShuttingDown,
        }
    }
}

/// Classifies one observation of the funding account, or returns `None` while the transaction can
/// still commit.
///
/// `block` is the block at which the node observed the account state `observed`.
fn classify(
    transition: &AccountTransition,
    observed: Word,
    block: BlockNumber,
) -> Option<Inclusion> {
    if observed == transition.final_ {
        return Some(Inclusion::Committed);
    }

    if observed != transition.initial {
        return Some(Inclusion::Diverged { observed, block });
    }

    // The account is still at the initial state. A block after the expiration block can no longer
    // include the transaction. The expiration block itself can, and the observation is at that
    // block after the block is applied, so the transaction did not commit in it either.
    (block >= transition.expiration).then_some(Inclusion::Expired)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::asset::FungibleAsset;

    use super::*;

    const EXPIRATION: u32 = 100;

    fn transition() -> AccountTransition {
        AccountTransition {
            account_id: FungibleAsset::mock_issuer(),
            initial: Word::from([1u32; 4]),
            final_: Word::from([2u32; 4]),
            expiration: BlockNumber::from(EXPIRATION),
        }
    }

    #[test]
    fn the_final_state_is_committed() {
        let transition = transition();

        assert_eq!(
            classify(&transition, transition.final_, BlockNumber::from(EXPIRATION - 10)),
            Some(Inclusion::Committed)
        );
    }

    /// The account state decides, not the block. A transaction which commits in its expiration
    /// block is observed after that block and must not be reported as expired.
    #[test]
    fn the_final_state_is_committed_after_the_expiration_block() {
        let transition = transition();

        assert_eq!(
            classify(&transition, transition.final_, BlockNumber::from(EXPIRATION)),
            Some(Inclusion::Committed)
        );
        assert_eq!(
            classify(&transition, transition.final_, BlockNumber::from(EXPIRATION + 50)),
            Some(Inclusion::Committed)
        );
    }

    #[test]
    fn the_initial_state_before_the_expiration_block_keeps_waiting() {
        let transition = transition();

        assert_eq!(classify(&transition, transition.initial, BlockNumber::GENESIS), None);
        assert_eq!(
            classify(&transition, transition.initial, BlockNumber::from(EXPIRATION - 1)),
            None
        );
    }

    #[test]
    fn the_initial_state_at_the_expiration_block_is_expired() {
        let transition = transition();

        assert_eq!(
            classify(&transition, transition.initial, BlockNumber::from(EXPIRATION)),
            Some(Inclusion::Expired)
        );
    }

    #[test]
    fn the_initial_state_after_the_expiration_block_is_expired() {
        let transition = transition();

        assert_eq!(
            classify(&transition, transition.initial, BlockNumber::from(EXPIRATION + 1)),
            Some(Inclusion::Expired)
        );
    }

    /// Another writer moved the funding account. Waiting cannot resolve this, so the loop must stop
    /// instead of polling forever.
    #[test]
    fn an_unknown_state_is_diverged_at_any_block() {
        let transition = transition();
        let observed = Word::from([3u32; 4]);

        for block in [0, EXPIRATION - 1, EXPIRATION, EXPIRATION + 1] {
            let block = BlockNumber::from(block);
            assert_eq!(
                classify(&transition, observed, block),
                Some(Inclusion::Diverged { observed, block })
            );
        }
    }
}
