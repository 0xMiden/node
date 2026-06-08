use miden_protocol::Word;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{Account, AccountDelta};
use miden_protocol::block::account_tree::{AccountIdKey, AccountTree};
use miden_protocol::block::{
    BlockAccountUpdate,
    BlockBody,
    BlockHeader,
    BlockNumber,
    FeeParameters,
    OutputNoteBatch,
    SignedBlock,
};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature, SigningKey};
use miden_protocol::crypto::merkle::mmr::{Forest, MmrPeaks};
use miden_protocol::crypto::merkle::smt::Smt;
use miden_protocol::errors::AccountError;
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::{OrderedTransactionHeaders, OutputNote, TransactionKernel};

pub mod config;

// GENESIS STATE
// ================================================================================================

/// Represents the state at genesis, which will be used to derive the genesis block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisState {
    pub accounts: Vec<Account>,
    /// Notes created in the genesis block (e.g. the `CONFIG_AGG_BRIDGE` note that registers the
    /// native faucet with the bridge). Empty unless explicitly populated.
    pub output_notes: Vec<OutputNote>,
    pub fee_parameters: FeeParameters,
    pub version: u32,
    pub timestamp: u32,
    pub validator_key: PublicKey,
}

/// A type-safety wrapper ensuring that genesis block data can only be created from [`GenesisState`]
/// or validated from a [`SignedBlock`] via [`GenesisBlock::try_from`].
pub struct GenesisBlock(SignedBlock);

/// A genesis block with all data except the validator signature.
pub struct UnsignedGenesisBlock {
    header: BlockHeader,
    body: BlockBody,
}

impl UnsignedGenesisBlock {
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    pub fn into_block(self, signature: Signature) -> anyhow::Result<GenesisBlock> {
        anyhow::ensure!(
            signature.verify(self.header.commitment(), self.header.validator_key()),
            "genesis block signature verification failed",
        );

        Ok(GenesisBlock(SignedBlock::new(self.header, self.body, signature)?))
    }
}

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

        anyhow::ensure!(
            block
                .signature()
                .verify(block.header().commitment(), block.header().validator_key()),
            "genesis block signature verification failed",
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
        validator_key: PublicKey,
    ) -> Self {
        Self {
            accounts,
            output_notes: Vec::new(),
            fee_parameters,
            version,
            timestamp,
            validator_key,
        }
    }

    /// Returns the unsigned genesis block.
    pub fn into_unsigned_block(self) -> anyhow::Result<UnsignedGenesisBlock> {
        let accounts: Vec<BlockAccountUpdate> = self
            .accounts
            .iter()
            .map(|account| {
                let account_update_details = if account.id().is_private() {
                    AccountUpdateDetails::Private
                } else {
                    AccountUpdateDetails::Delta(AccountDelta::try_from(account.clone())?)
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

        // Wrap any genesis output notes into a single batch (batch index 0). The block note tree is
        // derived from the body below so the note index mapping stays consistent.
        let output_note_batches: Vec<OutputNoteBatch> = if self.output_notes.is_empty() {
            Vec::new()
        } else {
            vec![self.output_notes.iter().cloned().enumerate().collect()]
        };

        let empty_transactions = OrderedTransactionHeaders::new_unchecked(Vec::new());

        // Build the body first so the block note tree root can be derived from it.
        let body = BlockBody::new_unchecked(
            accounts,
            output_note_batches,
            empty_nullifiers,
            empty_transactions,
        );

        let header = BlockHeader::new(
            self.version,
            Word::empty(),
            BlockNumber::GENESIS,
            MmrPeaks::new(Forest::empty(), Vec::new()).unwrap().hash_peaks(),
            account_smt.root(),
            empty_nullifier_tree.root(),
            body.compute_block_note_tree().root(),
            Word::empty(),
            TransactionKernel.to_commitment(),
            self.validator_key,
            self.fee_parameters,
            self.timestamp,
        );

        Ok(UnsignedGenesisBlock { header, body })
    }

    /// Builds and signs the genesis block with a local secret key.
    pub fn into_block(self, signer: &SigningKey) -> anyhow::Result<GenesisBlock> {
        let unsigned_block = self.into_unsigned_block()?;
        let signature = signer.sign(unsigned_block.header().commitment());
        unsigned_block.into_block(signature)
    }
}
