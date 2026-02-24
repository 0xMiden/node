use miden_protocol::Word;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{Account, AccountDelta};
use miden_protocol::block::account_tree::{AccountTree, account_id_to_smt_key};
use miden_protocol::block::{
    BlockAccountUpdate,
    BlockBody,
    BlockHeader,
    BlockNoteTree,
    BlockNumber,
    BlockProof,
    FeeParameters,
    ProvenBlock,
};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;
use miden_protocol::crypto::merkle::mmr::{Forest, MmrPeaks};
use miden_protocol::crypto::merkle::smt::{LargeSmt, MemoryStorage, Smt};
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::{OrderedTransactionHeaders, TransactionKernel};

use crate::errors::GenesisError;

pub mod config;

// GENESIS STATE
// ================================================================================================

/// Represents the state at genesis, which will be used to derive the genesis block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisState<S> {
    pub accounts: Vec<Account>,
    pub fee_parameters: FeeParameters,
    pub version: u32,
    pub timestamp: u32,
    pub block_signer: S,
}

/// A type-safety wrapper ensuring that genesis block data can only be created from
/// [`GenesisState`].
pub struct GenesisBlock(ProvenBlock);

impl GenesisBlock {
    pub fn inner(&self) -> &ProvenBlock {
        &self.0
    }

    pub fn into_inner(self) -> ProvenBlock {
        self.0
    }
}

impl<S> GenesisState<S> {
    pub fn new(
        accounts: Vec<Account>,
        fee_parameters: FeeParameters,
        version: u32,
        timestamp: u32,
        signer: S,
    ) -> Self {
        Self {
            accounts,
            fee_parameters,
            version,
            timestamp,
            block_signer: signer,
        }
    }
}

impl GenesisState<SecretKey> {
    /// Returns the block header and the account SMT
    pub fn into_block(self) -> Result<GenesisBlock, GenesisError> {
        let accounts: Vec<BlockAccountUpdate> = self
            .accounts
            .iter()
            .map(|account| {
                let account_update_details = if account.id().is_public() {
                    AccountUpdateDetails::Delta(
                        AccountDelta::try_from(account.clone())
                            .map_err(GenesisError::AccountDelta)?,
                    )
                } else {
                    AccountUpdateDetails::Private
                };

                Ok(BlockAccountUpdate::new(
                    account.id(),
                    account.commitment(),
                    account_update_details,
                ))
            })
            .collect::<Result<Vec<_>, GenesisError>>()?;

        // Convert account updates to SMT entries using account_id_to_smt_key
        let smt_entries = accounts.iter().map(|update| {
            (account_id_to_smt_key(update.account_id()), update.final_state_commitment())
        });

        // Create LargeSmt with MemoryStorage
        let smt = LargeSmt::with_entries(MemoryStorage::default(), smt_entries)
            .expect("Failed to create LargeSmt for genesis accounts");

        let account_smt = AccountTree::new(smt).expect("Failed to create AccountTree for genesis");

        let empty_nullifiers: Vec<Nullifier> = Vec::new();
        let empty_nullifier_tree = Smt::new();

        let empty_output_notes = Vec::new();
        let empty_block_note_tree = BlockNoteTree::empty();

        let empty_transactions = OrderedTransactionHeaders::new_unchecked(Vec::new());

        let header = BlockHeader::new(
            self.version,
            Word::empty(),
            BlockNumber::GENESIS,
            MmrPeaks::new(Forest::empty(), Vec::new()).unwrap().hash_peaks(),
            account_smt.root(),
            empty_nullifier_tree.root(),
            empty_block_note_tree.root(),
            Word::empty(),
            TransactionKernel.to_commitment(),
            self.block_signer.public_key(),
            self.fee_parameters,
            self.timestamp,
        );

        let body = BlockBody::new_unchecked(
            accounts,
            empty_output_notes,
            empty_nullifiers,
            empty_transactions,
        );

        let block_proof = BlockProof::new_dummy();

        let signature = self.block_signer.sign(header.commitment());
        // SAFETY: Header and accounts should be valid by construction.
        // No notes or nullifiers are created at genesis, which is consistent with the above empty
        // block note tree root and empty nullifier tree root.
        Ok(GenesisBlock(ProvenBlock::new_unchecked(header, body, signature, block_proof)))
    }
}
