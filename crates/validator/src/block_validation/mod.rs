use miden_node_db::{DatabaseError, Db};
use miden_protocol::block::{BlockHeader, BlockNumber, ProposedBlock};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::Signature;
use miden_protocol::errors::ProposedBlockError;
use miden_protocol::transaction::{TransactionHeader, TransactionId};
use tracing::instrument;

use crate::db::{find_unvalidated_transactions, load_block_header};
use crate::{COMPONENT, ValidatorSigner};

// BLOCK VALIDATION ERROR
// ================================================================================================

#[derive(thiserror::Error, Debug)]
pub enum BlockValidationError {
    #[error("block contains unvalidated transactions {0:?}")]
    UnvalidatedTransactions(Vec<TransactionId>),
    #[error("failed to build block")]
    BlockBuildingFailed(#[source] ProposedBlockError),
    #[error("failed to sign block: {0}")]
    BlockSigningFailed(String),
    #[error("failed to select transactions")]
    DatabaseError(#[source] DatabaseError),
    #[error("block number mismatch: expected {expected}, got {actual}")]
    BlockNumberMismatch {
        expected: BlockNumber,
        actual: BlockNumber,
    },
    #[error("previous block commitment does not match chain tip")]
    PrevBlockCommitmentMismatch,
    #[error("no previous block header available for chain tip overwrite")]
    NoPrevBlockHeader,
}

// BLOCK VALIDATION
// ================================================================================================

/// Validates a proposed block by checking:
/// 1. All transactions have been previously validated by this validator.
/// 2. The block header can be successfully built from the proposed block.
/// 3. The block is either: a. The valid next block in the chain (sequential block number, matching
///    previous block commitment), or b. A replacement block at the same height as the current chain
///    tip, validated against the previous block header.
///
/// On success, returns the signature and the validated block header.
#[instrument(target = COMPONENT, skip_all, err, fields(chain_tip = chain_tip.block_num().as_u32()))]
pub async fn validate_block(
    proposed_block: ProposedBlock,
    signer: &ValidatorSigner,
    db: &Db,
    chain_tip: BlockHeader,
) -> Result<(Signature, BlockHeader), BlockValidationError> {
    // Search for any proposed transactions that have not previously been validated.
    let proposed_tx_ids =
        proposed_block.transactions().map(TransactionHeader::id).collect::<Vec<_>>();
    let unvalidated_txs = db
        .transact("find_unvalidated_transactions", move |conn| {
            find_unvalidated_transactions(conn, &proposed_tx_ids)
        })
        .await
        .map_err(BlockValidationError::DatabaseError)?;

    // All proposed transactions must have been validated.
    if !unvalidated_txs.is_empty() {
        return Err(BlockValidationError::UnvalidatedTransactions(unvalidated_txs));
    }

    // Build the block header.
    let (proposed_header, _) = proposed_block
        .into_header_and_body()
        .map_err(BlockValidationError::BlockBuildingFailed)?;

    // If the proposed block has the same block number as the current chain tip, this is a
    // replacement block. Validate it against the previous block header.
    let prev = if proposed_header.block_num() == chain_tip.block_num() {
        let prev_block_num =
            chain_tip.block_num().parent().ok_or(BlockValidationError::NoPrevBlockHeader)?;
        db.query("load_block_header", move |conn| load_block_header(conn, prev_block_num))
            .await
            .map_err(BlockValidationError::DatabaseError)?
            .ok_or(BlockValidationError::NoPrevBlockHeader)?
    } else {
        // Proposed block is a new block.
        // Block number must be sequential.
        let expected_block_num = chain_tip.block_num().child();
        if proposed_header.block_num() != expected_block_num {
            return Err(BlockValidationError::BlockNumberMismatch {
                expected: expected_block_num,
                actual: proposed_header.block_num(),
            });
        }
        // Current chain tip is the parent of the proposed block.
        chain_tip
    };

    // The proposed block's parent must match the block that the Validator has determined is its
    // parent (either chain tip or parent of chain tip).
    if proposed_header.prev_block_commitment() != prev.commitment() {
        return Err(BlockValidationError::PrevBlockCommitmentMismatch);
    }

    let signature = sign_header(signer, &proposed_header).await?;
    Ok((signature, proposed_header))
}

/// Signs a block header using the validator's signer.
#[instrument(target = COMPONENT, name = "sign_block", skip_all, err, fields(block.number = header.block_num().as_u32()))]
async fn sign_header(
    signer: &ValidatorSigner,
    header: &BlockHeader,
) -> Result<Signature, BlockValidationError> {
    signer
        .sign(header)
        .await
        .map_err(|err| BlockValidationError::BlockSigningFailed(err.to_string()))
}
