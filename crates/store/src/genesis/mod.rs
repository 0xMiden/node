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
    ValidatorConfig,
};
use miden_protocol::crypto::merkle::mmr::{Forest, MmrPeaks};
use miden_protocol::crypto::merkle::smt::Smt;
use miden_protocol::note::Nullifier;
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::OrderedTransactionHeaders;

pub mod config;

pub use miden_node_utils::genesis::GenesisBlock;

// GENESIS STATE
// ================================================================================================

/// Represents the state at genesis, which will be used to derive the genesis block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisState {
    pub accounts: Vec<Account>,
    pub fee_parameters: FeeParameters,
    pub timestamp: u32,
    pub validator_config: ValidatorConfig,
    pub protocol_config: ProtocolConfig,
}

impl GenesisState {
    pub fn new(
        accounts: Vec<Account>,
        fee_parameters: FeeParameters,
        timestamp: u32,
        validator_config: ValidatorConfig,
        protocol_config: ProtocolConfig,
    ) -> Self {
        Self {
            accounts,
            fee_parameters,
            timestamp,
            validator_config,
            protocol_config,
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
            .map(|account| -> anyhow::Result<_> {
                let account_update_details = if account.id().is_private() {
                    AccountUpdateDetails::Private
                } else {
                    AccountUpdateDetails::Public(AccountPatch::try_from(account.clone())?)
                };

                Ok(BlockAccountUpdate::new(
                    account.id(),
                    account.to_commitment(),
                    account_update_details,
                )?)
            })
            .collect::<Result<Vec<_>, _>>()?;

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

        let validator_config = self.validator_config;

        let header = BlockHeader::new(
            Word::empty(),
            BlockNumber::GENESIS,
            MmrPeaks::new(Forest::empty(), Vec::new()).unwrap().hash_peaks(),
            account_smt.root(),
            empty_nullifier_tree.root(),
            empty_block_note_tree.root(),
            empty_transactions.commitment(),
            validator_config,
            self.fee_parameters,
            self.protocol_config.to_commitment(),
            None,
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

        GenesisBlock::new(SignedBlock::new(header, body, signatures)?, self.protocol_config)
    }
}
