use miden_protocol::Word;
use miden_protocol::account::{Account, AccountPatch, AccountUpdateDetails};
use miden_protocol::block::account_tree::{AccountIdKey, AccountTree};
use miden_protocol::block::{
    BlockAccountUpdate,
    BlockBody,
    BlockHeader,
    BlockNoteTree,
    BlockNumber,
    BlockSignatures,
    FeeParameters,
    SignedBlock,
    ValidatorKeys,
};
use miden_protocol::crypto::merkle::mmr::{Forest, MmrPeaks};
use miden_protocol::crypto::merkle::smt::Smt;
use miden_protocol::errors::AccountError;
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::{OrderedTransactionHeaders, TransactionKernel};

pub mod config;
pub mod pass_through;

// GENESIS STATE
// ================================================================================================

/// Represents the state at genesis, which will be used to derive the genesis block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisState {
    pub accounts: Vec<Account>,
    pub fee_parameters: FeeParameters,
    pub version: u32,
    pub timestamp: u32,
    pub validator_keys: ValidatorKeys,
}

/// A type-safety wrapper ensuring that genesis block data can only be created from [`GenesisState`]
/// or validated from a [`SignedBlock`] via [`GenesisBlock::try_from`].
#[derive(Debug)]
pub struct GenesisBlock(SignedBlock);

impl GenesisBlock {
    pub fn inner(&self) -> &SignedBlock {
        &self.0
    }

    pub fn into_inner(self) -> SignedBlock {
        self.0
    }
}

impl TryFrom<SignedBlock> for GenesisBlock {
    type Error = anyhow::Error;

    fn try_from(block: SignedBlock) -> anyhow::Result<Self> {
        anyhow::ensure!(
            block.header().block_num() == BlockNumber::GENESIS,
            "expected genesis block number (0), got {}",
            block.header().block_num(),
        );

        // The genesis block has no parent and is not signed: it acts as the chain's trust root and
        // must be obtained from a trusted source. Its header commits to the validator set, which is
        // required to sign every block after genesis.
        anyhow::ensure!(
            block.signatures().is_empty(),
            "genesis block must not carry signatures, got {}",
            block.signatures().len(),
        );

        Ok(Self(block))
    }
}

impl GenesisState {
    pub fn new(
        accounts: Vec<Account>,
        fee_parameters: FeeParameters,
        version: u32,
        timestamp: u32,
        validator_keys: ValidatorKeys,
    ) -> Self {
        Self {
            accounts,
            fee_parameters,
            version,
            timestamp,
            validator_keys,
        }
    }

    /// Builds the genesis block.
    ///
    /// The genesis block has no parent and is not signed: it acts as the chain's trust root and
    /// must be obtained from a trusted source. Its header commits to the validator set, which is
    /// required to sign every block after genesis.
    pub fn into_block(self) -> anyhow::Result<GenesisBlock> {
        let accounts: Vec<BlockAccountUpdate> = self
            .accounts
            .iter()
            .map(|account| {
                let account_update_details = if account.id().is_private() {
                    AccountUpdateDetails::Private
                } else {
                    AccountUpdateDetails::Public(AccountPatch::try_from(account.clone())?)
                };

                Ok(BlockAccountUpdate::new(
                    account.id(),
                    account.to_commitment(),
                    account_update_details,
                ))
            })
            .collect::<Result<Vec<_>, AccountError>>()?;

        // Convert account updates to SMT entries using account_id_to_smt_key
        let smt_entries = accounts.iter().map(|update| {
            (
                AccountIdKey::from(update.account_id()).as_word(),
                update.final_state_commitment(),
            )
        });

        let smt =
            Smt::with_entries(smt_entries).expect("Failed to create LargeSmt for genesis accounts");

        let account_smt = AccountTree::new(smt).expect("Failed to create AccountTree for genesis");

        let empty_nullifiers: Vec<Nullifier> = Vec::new();
        let empty_nullifier_tree = Smt::new();

        let empty_output_notes = Vec::new();
        let empty_block_note_tree = BlockNoteTree::empty();

        let empty_transactions = OrderedTransactionHeaders::new_unchecked(Vec::new());

        let validator_keys = self.validator_keys;

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
            validator_keys,
            self.fee_parameters,
            self.timestamp,
        );

        let body = BlockBody::new_unchecked(
            accounts,
            empty_output_notes,
            empty_nullifiers,
            empty_transactions,
        );

        let signatures = BlockSignatures::new(Vec::new())
            .map_err(|err| anyhow::anyhow!("failed to build empty genesis signatures: {err}"))?;

        Ok(GenesisBlock(SignedBlock::new(header, body, signatures)?))
    }
}
