//! Drives increments against the seeded counter account.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::{
    Account,
    AccountId,
    PartialAccount,
    StorageMapKey,
    StorageMapWitness,
    StorageSlotContent,
};
use miden_protocol::asset::{AssetId, AssetWitness};
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachments,
    NoteRecipient,
    NoteScript,
    NoteScriptRoot,
    NoteStorage,
    NoteType,
    PartialNote,
    PartialNoteMetadata,
};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{
    AccountInputs,
    InputNotes,
    PartialBlockchain,
    TransactionArgs,
    TransactionScript,
};
use miden_protocol::utils::serde::Serializable;
use miden_protocol::vm::FutureMaybeSend;
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::{FeeConversionInfo, commit_fee_conversion_info};
use miden_standards::account::fees::FeePolicyManager;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};
use miden_tx::auth::BasicAuthenticator;
use miden_tx::{
    DataStore,
    DataStoreError,
    LoadedMastForest,
    LocalTransactionProver,
    MastForestStore,
    TransactionExecutor,
    TransactionMastStore,
};
use rand::RngExt;
use rand_chacha::ChaCha20Rng;

use crate::accounts::{
    COUNTER_SLOT,
    WALLET_COUNTER_COMPONENT_PATH,
    create_increment_script,
    wallet_counter_component_code,
};
use crate::rpc::SubmissionClient;

/// Everything one increment needs, carried across iterations of the loop.
pub struct Driver {
    wallet: Account,
    counter: Account,
    /// Proves the counter's inclusion in the genesis account tree, which every increment references
    /// as its FPI anchor. Genesis commits the counter, so the anchor is valid from the first block
    /// and stays valid as later increments change the live state.
    counter_witness: AccountWitness,
    secret_key: SecretKey,
    increment_script: NoteScript,
    genesis_header: BlockHeader,
    protocol_config: ProtocolConfig,
    prover: LocalTransactionProver,
    rng: ChaCha20Rng,
}

impl Driver {
    pub async fn new(
        wallet: Account,
        counter: Account,
        secret_key: SecretKey,
        client: &SubmissionClient,
        rng: ChaCha20Rng,
    ) -> Result<Self> {
        let genesis_header = client.genesis_header().clone();
        let counter_witness = client
            .account_witness(counter.id(), genesis_header.block_num())
            .await
            .context("failed to fetch the counter's genesis account witness")?;

        anyhow::ensure!(
            counter_witness.state_commitment() == counter.to_commitment(),
            "the chain's genesis state for counter account {} does not match the seeded \
             counter.mac; the accounts directory and the running chain were seeded separately",
            counter.id(),
        );

        let fee_asset_id = counter
            .storage()
            .get_item(FeePolicyManager::fee_asset_id_slot())
            .context("counter account is missing its fee asset ID")?
            .try_into()
            .context("counter account carries an invalid fee asset ID")?;
        let protocol_config = ProtocolConfig::current(fee_asset_id)
            .context("failed to construct the current protocol configuration")?;
        anyhow::ensure!(
            protocol_config.to_commitment() == genesis_header.protocol_config_commitment(),
            "the counter's fee asset does not match the chain's protocol configuration",
        );

        Ok(Self {
            wallet,
            counter,
            counter_witness,
            secret_key,
            increment_script: create_increment_script()
                .context("failed to compile the increment note script")?,
            genesis_header,
            protocol_config,
            prover: LocalTransactionProver::default(),
            rng,
        })
    }

    /// The wallet in its current local state, for persisting between increments.
    pub fn wallet(&self) -> &Account {
        &self.wallet
    }

    /// Reads the counter account's on-chain value.
    ///
    /// This only advances once the ntx-builder has loaded the large account and consumed one of the
    /// network notes, so it is the signal that the harness is exercising what it means to.
    pub async fn observed_counter(&self, client: &SubmissionClient) -> Result<Option<u64>> {
        client.slot_value(self.counter.id(), COUNTER_SLOT).await
    }

    /// Builds, proves, and submits one increment, then advances the local wallet by the resulting
    /// patch. Returns the accepted block height and how long proving took.
    pub async fn submit_one(&mut self, client: &SubmissionClient) -> Result<Submitted> {
        let (network_note, recipient) = create_network_note(
            &self.wallet,
            &self.counter,
            self.increment_script.clone(),
            &mut self.rng,
        )?;

        let script = create_increment_tx_script(&network_note)?;
        let mut tx_args = TransactionArgs::default().with_tx_script(script);

        // The wallet's auth procedure pays the transaction fee in the chain's native asset. It
        // reads the conversion rate from the advice map, keyed by a commitment it recomputes from
        // the auth args, so both halves have to be supplied.
        let (auth_args, conversion_info_preimage) = self.fee_conversion_auth_args();
        tx_args = tx_args.with_auth_args(auth_args);
        tx_args.extend_advice_map([(auth_args, conversion_info_preimage)]);
        tx_args.add_output_note_recipient(Box::new(recipient));

        let mut data_store = DriverDataStore::new(
            self.genesis_header.clone(),
            self.protocol_config.clone(),
            PartialBlockchain::default(),
        );
        data_store.add_account(self.wallet.clone());
        // The counter is *foreign* to this transaction: creating a note targeted at it makes the
        // wallet's auth procedure price the note through the counter's `estimate_note_fee` via FPI.
        data_store.add_foreign_account(self.counter.clone(), self.counter_witness.clone());

        let authenticator =
            BasicAuthenticator::new(&[AuthSecretKey::Falcon512Poseidon2(self.secret_key.clone())]);
        let executor = TransactionExecutor::new(&data_store).with_authenticator(&authenticator);

        let executed = executor
            .execute_transaction(
                self.wallet.id(),
                self.genesis_header.block_num(),
                InputNotes::default(),
                tx_args,
            )
            .await
            .context("failed to execute the increment transaction")?;

        let tx_inputs = executed.tx_inputs().to_bytes();
        let patch = executed.account_patch().clone();

        let proving_started = Instant::now();
        let proven = self.prover.prove(executed).context("failed to prove the transaction")?;
        let proving_time = proving_started.elapsed();

        let block_num = client.submit(&proven, &tx_inputs).await?;

        self.wallet
            .apply_patch(&patch)
            .context("failed to apply the transaction patch to the local wallet")?;

        Ok(Submitted {
            tx_id: proven.id().to_hex(),
            block_num,
            proving_time,
        })
    }

    /// Builds the auth args committing to paying the fee in the chain's native asset at rate 1/1,
    /// together with the advice-map preimage the auth procedure verifies against them in-VM.
    fn fee_conversion_auth_args(&mut self) -> (Word, Vec<Felt>) {
        let fee_faucet_id = self.protocol_config.fee_asset_id().faucet_id();
        // The salt keeps the auth args usable as a per-transaction unique value for replay
        // protection.
        let salt = Word::new([
            Felt::new_unchecked(self.rng.random()),
            Felt::new_unchecked(self.rng.random()),
            Felt::new_unchecked(self.rng.random()),
            Felt::new_unchecked(self.rng.random()),
        ]);

        commit_fee_conversion_info(FeeConversionInfo::one_to_one(fee_faucet_id), salt)
    }
}

/// The outcome of one accepted increment.
pub struct Submitted {
    pub tx_id: String,
    pub block_num: BlockNumber,
    pub proving_time: Duration,
}

// NOTE + SCRIPT CONSTRUCTION
// ================================================================================================

/// Builds the network note addressed to the counter account.
///
/// The `NetworkAccountTarget` attachment is what makes this a *network* note: the ntx-builder watches
/// for notes targeting network accounts and authors the consuming transaction itself.
fn create_network_note(
    wallet: &Account,
    counter: &Account,
    script: NoteScript,
    rng: &mut ChaCha20Rng,
) -> Result<(Note, NoteRecipient)> {
    let target = NetworkAccountTarget::new(counter.id(), NoteExecutionHint::Always)
        .context("counter account should be a valid network target")?;
    let attachment: NoteAttachment = target.into();
    let attachments = NoteAttachments::from(attachment);

    let partial_metadata = PartialNoteMetadata::new(wallet.id(), NoteType::Public);

    let serial_num = Word::new([
        Felt::new_unchecked(rng.random()),
        Felt::new_unchecked(rng.random()),
        Felt::new_unchecked(rng.random()),
        Felt::new_unchecked(rng.random()),
    ]);

    let recipient = NoteRecipient::new(serial_num, script, NoteStorage::new(vec![])?);
    let note = Note::with_attachments(
        NoteAssets::new(vec![])?,
        partial_metadata,
        recipient.clone(),
        attachments,
    );

    Ok((note, recipient))
}

/// Builds the transaction script for one increment.
///
/// The whole transaction is a single `call` into the wallet's `increment_and_create_note` procedure,
/// which creates the network note and bumps the wallet's counter slot atomically.
fn create_increment_tx_script(network_note: &Note) -> Result<TransactionScript> {
    let wallet_component = wallet_counter_component_code()?;

    let partial: PartialNote = network_note.clone().into();
    let recipient = partial.recipient_digest();
    let note_type = Felt::from(partial.metadata().note_type());
    let tag = Felt::from(partial.metadata().tag());

    // `increment_and_create_note` shares `create_note`'s stack contract: it consumes `[tag,
    // note_type, RECIPIENT, pad(10)]` and returns `[note_idx, pad(15)]`. The padding is built
    // explicitly and the trailing pads reduced back to `[note_idx]`, otherwise they survive on the
    // overflow stack and `main` returns at the wrong depth.
    let call_target = format!("::{WALLET_COUNTER_COMPONENT_PATH}::increment_and_create_note");
    let mut note_section = format!(
        "
        padw padw push.0.0
        push.{recipient}
        push.{note_type}
        push.{tag}
        # => [tag, note_type, RECIPIENT, pad(10)]
        call.{call_target}
        # => [note_idx, pad(15)]
        movdn.15 dropw dropw dropw drop drop drop
        # => [note_idx]
        "
    );

    for attachment in partial.attachments().iter() {
        let scheme = attachment.attachment_scheme().as_u16();
        let commitment = attachment.content().to_commitment();
        // `add_attachment` consumes `[attachment_scheme, ATTACHMENT_COMMITMENT, note_idx]`, so dup
        // the note index for it to consume and keep our own copy for the next attachment / the
        // drop.
        write!(
            note_section,
            "
        dup
        push.{commitment}
        push.{scheme}
        # => [attachment_scheme, ATTACHMENT_COMMITMENT, note_idx, note_idx]
        exec.::miden::protocol::output_note::add_attachment
        # => [note_idx]
        "
        )
        .expect("writing to a String cannot fail");
    }
    note_section.push_str("        drop\n");

    let script_src = format!(
        "@transaction_script
        pub proc main
{note_section}
        end"
    );

    let mut code_builder = CodeBuilder::new()
        .with_dynamically_linked_package(&wallet_component)
        .context("failed to dynamically link the wallet counter component")?;

    // Attachments are resolved at runtime from the advice map, keyed by their commitment.
    for attachment in partial.attachments().iter() {
        code_builder.add_advice_map_entry(attachment.to_commitment(), attachment.to_elements());
    }

    code_builder
        .compile_tx_script(script_src)
        .context("failed to compile the increment transaction script")
}

// DATA STORE
// ================================================================================================

/// An in-memory [`DataStore`] over the genesis header and the two accounts involved.
///
/// The transaction consumes no input notes and reads no storage maps, so only the account,
/// blockchain, foreign-account and vault-witness methods need real implementations.
struct DriverDataStore {
    accounts: HashMap<AccountId, Account>,
    account_witnesses: HashMap<AccountId, AccountWitness>,
    block_header: BlockHeader,
    protocol_config: ProtocolConfig,
    partial_blockchain: PartialBlockchain,
    mast_store: TransactionMastStore,
}

impl DriverDataStore {
    fn new(
        block_header: BlockHeader,
        protocol_config: ProtocolConfig,
        partial_blockchain: PartialBlockchain,
    ) -> Self {
        Self {
            accounts: HashMap::new(),
            account_witnesses: HashMap::new(),
            block_header,
            protocol_config,
            partial_blockchain,
            mast_store: TransactionMastStore::new(),
        }
    }

    fn add_account(&mut self, account: Account) {
        self.mast_store.load_account_code(account.code());
        self.accounts.insert(account.id(), account);
    }

    /// Registers an account the transaction reaches through a foreign procedure invocation,
    /// together with the account-tree witness proving its state in the reference block.
    fn add_foreign_account(&mut self, account: Account, witness: AccountWitness) {
        self.add_account(account);
        self.account_witnesses.insert(witness.id(), witness);
    }

    fn account(&self, account_id: AccountId) -> Result<&Account, DataStoreError> {
        self.accounts.get(&account_id).ok_or_else(|| DataStoreError::Other {
            error_msg: "unknown account".into(),
            source: None,
        })
    }
}

impl DataStore for DriverDataStore {
    fn get_transaction_inputs(
        &self,
        account_id: AccountId,
        _block_refs: BTreeSet<BlockNumber>,
    ) -> impl FutureMaybeSend<
        Result<(PartialAccount, BlockHeader, ProtocolConfig, PartialBlockchain), DataStoreError>,
    > {
        async move {
            let account = self.account(account_id)?;

            Ok((
                PartialAccount::from(account),
                self.block_header.clone(),
                self.protocol_config.clone(),
                self.partial_blockchain.clone(),
            ))
        }
    }

    /// Opens a map slot of the requested account by root.
    ///
    /// Reached through the counter's fee policy: `estimate_note_fee` looks the note's script root up
    /// in the `basic_constant_fee` schedule, which is a storage map.
    fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        map_root: Word,
        map_key: StorageMapKey,
    ) -> impl FutureMaybeSend<Result<StorageMapWitness, DataStoreError>> {
        async move {
            let account = self.account(account_id)?;

            account
                .storage()
                .slots()
                .iter()
                .filter_map(|slot| match slot.content() {
                    StorageSlotContent::Map(map) => Some(map),
                    StorageSlotContent::Value(_) => None,
                })
                .find(|map| map.root() == map_root)
                .map(|map| map.open(&map_key))
                .ok_or_else(|| DataStoreError::Other {
                    error_msg: format!(
                        "no storage map with root {map_root} in account {account_id}"
                    )
                    .into(),
                    source: None,
                })
        }
    }

    fn get_foreign_account_inputs(
        &self,
        foreign_account_id: AccountId,
        _ref_block: BlockNumber,
    ) -> impl FutureMaybeSend<Result<AccountInputs, DataStoreError>> {
        async move {
            let account = self.account(foreign_account_id)?;
            let witness =
                self.account_witnesses.get(&foreign_account_id).cloned().ok_or_else(|| {
                    DataStoreError::Other {
                        error_msg: format!(
                            "no account witness for foreign account {foreign_account_id}"
                        )
                        .into(),
                        source: None,
                    }
                })?;

            Ok(AccountInputs::new(PartialAccount::from(account), witness))
        }
    }

    fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        vault_root: Word,
        vault_keys: BTreeSet<AssetId>,
    ) -> impl FutureMaybeSend<Result<Vec<AssetWitness>, DataStoreError>> {
        async move {
            let account = self.account(account_id)?;

            if account.vault().root() != vault_root {
                return Err(DataStoreError::other("vault root mismatch"));
            }

            vault_keys
                .into_iter()
                .map(|vault_key| {
                    AssetWitness::new(account.vault().open(vault_key).into(), [vault_key]).map_err(
                        |err| DataStoreError::Other {
                            error_msg: "failed to open the vault asset tree".into(),
                            source: Some(Box::new(err)),
                        },
                    )
                })
                .collect::<Result<Vec<_>, _>>()
        }
    }

    fn get_note_script(
        &self,
        _script_root: NoteScriptRoot,
    ) -> impl FutureMaybeSend<Result<Option<NoteScript>, DataStoreError>> {
        async move { Ok(None) }
    }
}

impl MastForestStore for DriverDataStore {
    fn get(&self, procedure_hash: &Word) -> Option<LoadedMastForest> {
        self.mast_store.get(procedure_hash)
    }
}
