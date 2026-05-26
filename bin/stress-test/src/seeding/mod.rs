use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use metrics::SeedingMetrics;
use miden_node_proto::domain::batch::BatchInputs;
use miden_node_proto::generated::store::rpc_client::RpcClient;
use miden_node_store::state::State;
use miden_node_store::{DataDirectory, GenesisState, Store, StoreMode};
use miden_node_utils::clap::{GrpcOptionsInternal, StorageOptions};
use miden_node_utils::tracing::grpc::OtelInterceptor;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountComponentMetadata,
    AccountDelta,
    AccountId,
    AccountStorageDelta,
    AccountType,
    AccountVaultDelta,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{Asset, FungibleAsset, TokenSymbol};
use miden_protocol::batch::{BatchAccountUpdate, BatchId, ProvenBatch};
use miden_protocol::block::{
    BlockHeader,
    BlockInputs,
    BlockNumber,
    FeeParameters,
    ProposedBlock,
    SignedBlock,
};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey as EcdsaSecretKey;
use miden_protocol::crypto::dsa::falcon512_poseidon2::{PublicKey, SecretKey};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::errors::AssetError;
use miden_protocol::note::{Note, NoteAssets, NoteId, NoteInclusionProof};
use miden_protocol::transaction::{
    InputNote,
    InputNoteCommitment,
    InputNotes,
    OrderedTransactionHeaders,
    OutputNote,
    ProvenTransaction,
    PublicOutputNote,
    TransactionHeader,
    TxAccountUpdate,
};
use miden_protocol::utils::serde::Serializable;
use miden_protocol::vm::ExecutionProof;
use miden_protocol::{Felt, ONE, Word};
use miden_standards::account::auth::AuthSingleSig;
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BurnPolicyConfig,
    MintPolicyConfig,
    PolicyRegistration,
    TokenPolicyManager,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::P2idNote;
use rand::Rng;
use rand::seq::SliceRandom;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::prelude::ParallelSlice;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::{fs, task};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use url::Url;

mod metrics;
#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

const BATCHES_PER_BLOCK: usize = 16;
const TRANSACTIONS_PER_BATCH: usize = 16;

pub const ACCOUNTS_FILENAME: &str = "accounts.txt";

pub const BENCHMARK_STORAGE_MAP_SLOT_NAME: &str = "miden::mock::stress_test::map";

// SEED STORE
// ================================================================================================

/// Seeds the store with a given number of accounts.
pub async fn seed_store(
    data_directory: PathBuf,
    num_accounts: usize,
    public_accounts_percentage: u8,
    storage_map_entries: usize,
    vault_entries: usize,
    account_update_blocks: usize,
) {
    let start = Instant::now();
    assert!(
        vault_entries <= NoteAssets::MAX_NUM_ASSETS,
        "--vault-entries must be at most {}",
        NoteAssets::MAX_NUM_ASSETS
    );

    // Recreate the data directory (it should be empty for store bootstrapping).
    //
    // Ignore the error since it will also error if it does not exist.
    let _ = fs_err::remove_dir_all(&data_directory);
    fs_err::create_dir_all(&data_directory).expect("created data directory");

    // generate the faucet account and the genesis state
    let benchmark_faucets = create_benchmark_faucets(vault_entries);
    let faucet = benchmark_faucets[0].clone();
    let asset_faucet_ids = benchmark_faucets.iter().map(Account::id).collect::<Vec<_>>();
    let fee_params = FeeParameters::new(faucet.id(), 0);
    let signer = EcdsaSecretKey::new();
    let genesis_state = GenesisState::new(benchmark_faucets, fee_params, 1, 1, signer.public_key());
    let genesis_block = genesis_state
        .clone()
        .into_block(&signer)
        .expect("genesis block should be created");
    Store::bootstrap(genesis_block, &data_directory).expect("store should bootstrap");

    let store_state = load_state(data_directory.clone()).await;

    // start generating blocks
    let accounts_filepath = data_directory.join(ACCOUNTS_FILENAME);
    let data_directory =
        miden_node_store::DataDirectory::load(data_directory).expect("data directory should exist");
    let genesis_header = genesis_state.into_block(&signer).unwrap().into_inner();
    let metrics = generate_blocks(
        num_accounts,
        public_accounts_percentage,
        faucet,
        genesis_header,
        &store_state,
        data_directory,
        accounts_filepath,
        &signer,
        storage_map_entries,
        vault_entries,
        account_update_blocks,
        asset_faucet_ids,
    )
    .await;

    println!("Total time: {:.3} seconds", start.elapsed().as_secs_f64());
    println!("{metrics}");
}

/// Generates batches of transactions to be inserted into the store.
///
/// The first transaction in each batch sends assets from the faucet to 255 accounts.
/// The rest of the transactions consume the notes created by the faucet in the previous block.
#[expect(clippy::too_many_arguments)]
#[expect(clippy::too_many_lines)]
async fn generate_blocks(
    num_accounts: usize,
    public_accounts_percentage: u8,
    mut faucet: Account,
    genesis_block: SignedBlock,
    store_state: &Arc<State>,
    data_directory: DataDirectory,
    accounts_filepath: PathBuf,
    signer: &EcdsaSecretKey,
    storage_map_entries: usize,
    vault_entries: usize,
    account_update_blocks: usize,
    asset_faucet_ids: Vec<AccountId>,
) -> SeedingMetrics {
    // Each block is composed of [`BATCHES_PER_BLOCK`] batches, and each batch is composed of
    // [`TRANSACTIONS_PER_BATCH`] txs. The first note of the block is always a send assets tx from
    // the faucet to (BATCHES_PER_BLOCK * TRANSACTIONS_PER_BATCH) - 1 accounts. The rest of the
    // notes are consume note txs from the (BATCHES_PER_BLOCK * TRANSACTIONS_PER_BATCH) - 1 accounts
    // that were minted in the previous block.
    let mut metrics = SeedingMetrics::new(data_directory.database_path());

    let mut account_ids = vec![];
    let mut note_nullifiers = vec![];
    let mut account_states: BTreeMap<AccountId, Account> = BTreeMap::new();

    let mut consume_notes_txs: Vec<ProvenTransaction> = vec![];
    let mut pending_consumed_accounts: Vec<Account> = vec![];

    let consumes_per_block = TRANSACTIONS_PER_BATCH * BATCHES_PER_BLOCK - 1;
    #[expect(clippy::cast_sign_loss, clippy::cast_precision_loss)]
    let num_public_accounts = (consumes_per_block as f64
        * (f64::from(public_accounts_percentage) / 100.0))
        .round() as usize;
    let num_private_accounts = consumes_per_block - num_public_accounts;
    // +1 to account for the first block with the send assets tx only
    let total_blocks = (num_accounts / consumes_per_block) + 1;

    // share random coin seed and key pair for all accounts to avoid key generation overhead
    let coin_seed: [u64; 4] = rand::rng().random();
    let rng = Arc::new(Mutex::new(RandomCoin::new(coin_seed.map(Felt::new_unchecked).into())));
    let key_pair = {
        let mut rng = rng.lock().unwrap();
        SecretKey::with_rng(&mut *rng)
    };

    let mut prev_block_header = genesis_block.header().clone();
    let mut current_anchor_header = genesis_block.header().clone();

    for i in 0..total_blocks {
        let mut block_txs = Vec::with_capacity(BATCHES_PER_BLOCK * TRANSACTIONS_PER_BATCH);

        // create public accounts and notes that mint assets for these accounts
        let (pub_accounts, pub_notes) = create_accounts_and_notes(
            num_public_accounts,
            AccountType::Public,
            &key_pair,
            &rng,
            &asset_faucet_ids,
            i,
            storage_map_entries,
            vault_entries,
        );

        // create private accounts and notes that mint assets for these accounts
        let (priv_accounts, priv_notes) = create_accounts_and_notes(
            num_private_accounts,
            AccountType::Private,
            &key_pair,
            &rng,
            &asset_faucet_ids,
            i,
            storage_map_entries,
            vault_entries,
        );

        let notes = [pub_notes, priv_notes].concat();
        let accounts = [pub_accounts, priv_accounts].concat();
        account_ids.extend(accounts.iter().map(Account::id));
        note_nullifiers.extend(notes.iter().map(|n| n.nullifier().prefix()));

        // create the tx that creates the notes
        let emit_note_tx = create_emit_note_tx(&prev_block_header, &mut faucet, notes.clone());

        // collect all the txs
        block_txs.push(emit_note_tx);
        block_txs.extend(consume_notes_txs);

        // create the batches with [TRANSACTIONS_PER_BATCH] txs each
        let batches: Vec<ProvenBatch> = block_txs
            .par_chunks(TRANSACTIONS_PER_BATCH)
            .map(|txs| create_batch(txs, &prev_block_header))
            .collect();

        // create the block and send it to the store
        let block_inputs = get_block_inputs(store_state, &batches, &mut metrics).await;

        // update blocks
        prev_block_header =
            apply_block(batches, block_inputs, store_state, &mut metrics, signer).await;
        account_states
            .extend(pending_consumed_accounts.into_iter().map(|account| (account.id(), account)));
        if current_anchor_header.block_epoch() != prev_block_header.block_epoch() {
            current_anchor_header = prev_block_header.clone();
        }

        // create the consume notes txs to be used in the next block
        let batch_inputs =
            get_batch_inputs(store_state, &prev_block_header, &notes, &mut metrics).await;
        (pending_consumed_accounts, consume_notes_txs) = create_consume_note_txs(
            &prev_block_header,
            accounts,
            notes,
            &batch_inputs.note_proofs,
            None,
        );

        // track store size every 50 blocks
        if i % 50 == 0 {
            metrics.record_store_size();
        }
    }

    let update_note_faucet_ids =
        asset_faucet_ids.iter().take(vault_entries).copied().collect::<Vec<_>>();
    let mut random = rand::rng();
    for update_block_index in 0..account_update_blocks {
        let mut block_txs = Vec::with_capacity(BATCHES_PER_BLOCK * TRANSACTIONS_PER_BATCH);

        let selected_account_ids = select_random_account_ids_for_update_notes(
            &account_states,
            &pending_consumed_accounts,
            consumes_per_block,
            &mut random,
        );
        let notes = {
            let mut note_rng = rng.lock().unwrap();
            selected_account_ids
                .iter()
                .map(|account_id| create_note(&update_note_faucet_ids, *account_id, &mut note_rng))
                .collect::<Vec<_>>()
        };

        let emit_note_tx = create_emit_note_tx(&prev_block_header, &mut faucet, notes.clone());
        block_txs.push(emit_note_tx);
        block_txs.extend(consume_notes_txs);

        let batches: Vec<ProvenBatch> = block_txs
            .par_chunks(TRANSACTIONS_PER_BATCH)
            .map(|txs| create_batch(txs, &prev_block_header))
            .collect();

        let block_inputs = get_block_inputs(store_state, &batches, &mut metrics).await;

        prev_block_header =
            apply_block(batches, block_inputs, store_state, &mut metrics, signer).await;
        account_states
            .extend(pending_consumed_accounts.into_iter().map(|account| (account.id(), account)));
        if current_anchor_header.block_epoch() != prev_block_header.block_epoch() {
            current_anchor_header = prev_block_header.clone();
        }

        let batch_inputs =
            get_batch_inputs(store_state, &prev_block_header, &notes, &mut metrics).await;
        let accounts = selected_account_ids
            .iter()
            .filter_map(|account_id| account_states.get(account_id).cloned())
            .collect::<Vec<_>>();
        (pending_consumed_accounts, consume_notes_txs) = create_consume_note_txs(
            &prev_block_header,
            accounts,
            notes,
            &batch_inputs.note_proofs,
            Some(BenchmarkStorageUpdate {
                block_index: update_block_index,
                storage_map_entries,
            }),
        );

        if update_block_index % 50 == 0 {
            metrics.record_store_size();
        }
    }

    // dump account ids to a file
    let mut file = fs::File::create(accounts_filepath).await.unwrap();
    for id in account_ids {
        file.write_all(format!("{id}\n").as_bytes()).await.unwrap();
    }

    metrics
}

/// Given a list of batches and block inputs, creates a `ProvenBlock` and applies it to the store.
/// Tracks the insertion time on the metrics.
///
/// Returns the the inserted block.
async fn apply_block(
    batches: Vec<ProvenBatch>,
    block_inputs: BlockInputs,
    store_state: &Arc<State>,
    metrics: &mut SeedingMetrics,
    signer: &EcdsaSecretKey,
) -> BlockHeader {
    let proposed_block = ProposedBlock::new(block_inputs, batches).unwrap();
    let (header, body) = proposed_block.clone().into_header_and_body().unwrap();
    let block_size: usize = header.to_bytes().len() + body.to_bytes().len();
    let signature = signer.sign(header.commitment());
    // SAFETY: The header, body, and signature are known to correspond to each other.
    let signed_block = SignedBlock::new_unchecked(header, body, signature);
    let header = signed_block.header().clone();
    let ordered_batches = proposed_block.batches().clone();

    let start = Instant::now();
    store_state
        .apply_block_with_proving_inputs(ordered_batches, signed_block)
        .await
        .unwrap();
    metrics.track_block_insertion(start.elapsed(), block_size);

    header
}

// HELPER FUNCTIONS
// ================================================================================================

/// Extract the payable fee as `FungibleAsset` from the given `BlockHeader`.
fn fee_from_block(block_ref: &BlockHeader) -> Result<FungibleAsset, AssetError> {
    FungibleAsset::new(
        block_ref.fee_parameters().fee_faucet_id(),
        u64::from(block_ref.fee_parameters().verification_base_fee()),
    )
}

/// Creates `num_accounts` accounts, and for each one creates a note that mint assets.
///
/// Returns a tuple with:
/// - The list of new accounts
/// - The list of new notes
#[expect(clippy::too_many_arguments)]
fn create_accounts_and_notes(
    num_accounts: usize,
    account_type: AccountType,
    key_pair: &SecretKey,
    rng: &Arc<Mutex<RandomCoin>>,
    asset_faucet_ids: &[AccountId],
    block_num: usize,
    storage_map_entries: usize,
    vault_entries: usize,
) -> (Vec<Account>, Vec<Note>) {
    assert!(
        !asset_faucet_ids.is_empty(),
        "at least one faucet id is required to create benchmark notes"
    );
    let note_faucet_ids = match account_type {
        AccountType::Public => asset_faucet_ids.iter().take(vault_entries).copied().collect(),
        AccountType::Private => vec![asset_faucet_ids[0]],
    };

    (0..num_accounts)
        .into_par_iter()
        .map(|account_index| {
            let account = create_account(
                key_pair.public_key(),
                ((block_num * num_accounts) + account_index) as u64,
                account_type,
                storage_map_entries,
            );
            let note = {
                let mut rng = rng.lock().unwrap();
                create_note(&note_faucet_ids, account.id(), &mut rng)
            };
            (account, note)
        })
        .collect()
}

/// Creates a public P2ID note containing 10 tokens for each requested fungible asset and sends it
/// to the specified target account.
fn create_note(faucet_ids: &[AccountId], target_id: AccountId, rng: &mut RandomCoin) -> Note {
    let assets = faucet_ids
        .iter()
        .map(|faucet_id| Asset::Fungible(FungibleAsset::new(*faucet_id, 10).unwrap()))
        .collect();
    let sender = faucet_ids.first().copied().unwrap_or(target_id);
    P2idNote::create(
        sender,
        target_id,
        assets,
        miden_protocol::note::NoteType::Public,
        miden_protocol::note::NoteAttachments::empty(),
        rng,
    )
    .expect("note creation failed")
}

fn select_random_account_ids_for_update_notes<R: Rng + ?Sized>(
    account_states: &BTreeMap<AccountId, Account>,
    pending_accounts: &[Account],
    max_accounts: usize,
    rng: &mut R,
) -> Vec<AccountId> {
    let mut account_ids = account_states.keys().copied().collect::<Vec<_>>();
    for account in pending_accounts {
        let account_id = account.id();
        if !account_states.contains_key(&account_id) {
            account_ids.push(account_id);
        }
    }

    account_ids.shuffle(rng);
    account_ids.truncate(max_accounts);
    account_ids
}

#[derive(Clone, Copy)]
struct BenchmarkStorageUpdate {
    block_index: usize,
    storage_map_entries: usize,
}

fn benchmark_storage_map_update_value(block_index: usize, tx_index: usize, key_index: u32) -> Word {
    Word::from([
        Felt::ZERO,
        Felt::from(u32::try_from(block_index).expect("update block index fits into u32")),
        Felt::from(u32::try_from(tx_index).expect("transaction index fits into u32")),
        Felt::from(key_index),
    ])
}

fn update_benchmark_storage_map_entry(
    account: &mut Account,
    block_index: usize,
    tx_index: usize,
    storage_map_entries: usize,
) -> bool {
    if !account.is_public() || storage_map_entries == 0 {
        return false;
    }

    let key_index =
        u32::try_from((tx_index % storage_map_entries) + 1).expect("storage map key fits into u32");
    let key = StorageMapKey::from_index(key_index);
    let value = benchmark_storage_map_update_value(block_index, tx_index, key_index);

    account
        .storage_mut()
        .set_map_item(&benchmark_storage_map_slot(), key, value)
        .is_ok()
}

/// Creates a new account with a given public key and storage mode. Generates the seed from the
/// given index.
pub fn benchmark_storage_map_slot() -> StorageSlotName {
    StorageSlotName::new(BENCHMARK_STORAGE_MAP_SLOT_NAME).unwrap()
}

fn create_account(
    public_key: PublicKey,
    index: u64,
    account_type: AccountType,
    storage_map_entries: usize,
) -> Account {
    let init_seed: Vec<_> = index.to_be_bytes().into_iter().chain([0u8; 24]).collect();
    let mut builder = AccountBuilder::new(init_seed.try_into().unwrap())
        .account_type(account_type)
        .with_auth_component(AuthSingleSig::new(public_key.into(), AuthScheme::Falcon512Poseidon2))
        .with_component(BasicWallet);

    if account_type == AccountType::Public && storage_map_entries > 0 {
        let entries = (1..=storage_map_entries)
            .map(|i| {
                let i = u32::try_from(i).expect("storage map entry index fits into u32");
                (
                    StorageMapKey::from_index(i),
                    Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::from(i)]),
                )
            })
            .collect::<Vec<_>>();
        let storage_map = StorageMap::with_entries(entries).unwrap();
        let component_storage =
            vec![StorageSlot::with_map(benchmark_storage_map_slot(), storage_map)];
        let component_code = CodeBuilder::default()
            .compile_component_code("benchmark::storage_map", "pub proc noop push.0 drop end")
            .unwrap();
        let component = AccountComponent::new(
            component_code,
            component_storage,
            AccountComponentMetadata::new("benchmark_storage_map"),
        )
        .unwrap();
        builder = builder.with_component(component);
    }

    builder.build().unwrap()
}

fn create_benchmark_faucets(vault_entries: usize) -> Vec<Account> {
    (0..vault_entries.max(1))
        .map(|index| create_faucet_with_seed(index as u64))
        .collect()
}

fn create_faucet_with_seed(index: u64) -> Account {
    let coin_seed: [u64; 4] = rand::rng().random();
    let mut rng = RandomCoin::new(coin_seed.map(Felt::new_unchecked).into());
    let key_pair = SecretKey::with_rng(&mut rng);
    let init_seed: Vec<_> = index.to_be_bytes().into_iter().chain([0u8; 24]).collect();

    let token_symbol = TokenSymbol::new("TEST").unwrap();
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("TEST").unwrap())
        .symbol(token_symbol)
        .decimals(2)
        .max_supply(FungibleAsset::MAX_AMOUNT)
        .build()
        .unwrap();

    AccountBuilder::new(init_seed.try_into().unwrap())
        .account_type(AccountType::Private)
        .with_component(faucet)
        .with_components(
            TokenPolicyManager::new()
                .with_mint_policy(MintPolicyConfig::AllowAll, PolicyRegistration::Active)
                .unwrap()
                .with_burn_policy(BurnPolicyConfig::AllowAll, PolicyRegistration::Active)
                .unwrap(),
        )
        .with_auth_component(AuthSingleSig::new(
            key_pair.public_key().into(),
            AuthScheme::Falcon512Poseidon2,
        ))
        .build()
        .unwrap()
}

/// Creates a proven batch from a list of transactions and a reference block.
fn create_batch(txs: &[ProvenTransaction], block_ref: &BlockHeader) -> ProvenBatch {
    let account_updates = txs
        .iter()
        .map(|tx| (tx.account_id(), BatchAccountUpdate::from_transaction(tx)))
        .collect();
    let input_notes = txs.iter().flat_map(|tx| tx.input_notes().iter().cloned()).collect();
    let output_notes = txs.iter().flat_map(|tx| tx.output_notes().iter().cloned()).collect();
    ProvenBatch::new_unchecked(
        BatchId::from_transactions(txs.iter()),
        block_ref.commitment(),
        block_ref.block_num(),
        account_updates,
        InputNotes::new(input_notes).unwrap(),
        output_notes,
        BlockNumber::MAX,
        OrderedTransactionHeaders::new_unchecked(txs.iter().map(TransactionHeader::from).collect()),
    )
    .unwrap()
}

/// For each pair of account and note, creates a transaction that consumes the note.
fn create_consume_note_txs(
    block_ref: &BlockHeader,
    accounts: Vec<Account>,
    notes: Vec<Note>,
    note_proofs: &BTreeMap<NoteId, NoteInclusionProof>,
    storage_update: Option<BenchmarkStorageUpdate>,
) -> (Vec<Account>, Vec<ProvenTransaction>) {
    accounts
        .into_iter()
        .zip(notes)
        .enumerate()
        .map(|(tx_index, (account, note))| {
            let inclusion_proof = note_proofs.get(&note.id()).unwrap();
            create_consume_note_tx(
                block_ref,
                account,
                InputNote::authenticated(note, inclusion_proof.clone()),
                storage_update.map(|update| (update, tx_index)),
            )
        })
        .unzip()
}

/// Creates a transaction that creates an account and consumes the given input note.
///
/// The account is updated with the assets from the input note, and the nonce is incremented.
fn create_consume_note_tx(
    block_ref: &BlockHeader,
    mut account: Account,
    input_note: InputNote,
    storage_update: Option<(BenchmarkStorageUpdate, usize)>,
) -> (Account, ProvenTransaction) {
    let init_hash = account.initial_commitment();
    let is_new_account = account.is_new();

    input_note.note().assets().iter().for_each(|asset| {
        account.vault_mut().add_asset(*asset).unwrap();
    });

    if let Some((storage_update, tx_index)) = storage_update {
        update_benchmark_storage_map_entry(
            &mut account,
            storage_update.block_index,
            tx_index,
            storage_update.storage_map_entries,
        );
    }

    account.increment_nonce(ONE).unwrap();

    let (details, account_delta_commitment) = if account.is_public() {
        let account_delta = if is_new_account {
            AccountDelta::try_from(account.clone()).unwrap()
        } else {
            create_existing_account_delta(&account, input_note.note().assets(), storage_update)
        };
        let commitment = account_delta.clone().to_commitment();
        (AccountUpdateDetails::Delta(account_delta), commitment)
    } else {
        (AccountUpdateDetails::Private, Word::empty())
    };

    let account_update = TxAccountUpdate::new(
        account.id(),
        init_hash,
        account.to_commitment(),
        account_delta_commitment,
        details,
    )
    .unwrap();
    let transaction = ProvenTransaction::new(
        account_update,
        vec![InputNoteCommitment::from(input_note)],
        Vec::<OutputNote>::new(),
        block_ref.block_num(),
        block_ref.commitment(),
        fee_from_block(block_ref).unwrap(),
        u32::MAX.into(),
        ExecutionProof::new_dummy(),
    )
    .unwrap();

    (account, transaction)
}

fn create_existing_account_delta(
    account: &Account,
    note_assets: &NoteAssets,
    storage_update: Option<(BenchmarkStorageUpdate, usize)>,
) -> AccountDelta {
    let mut vault_delta = AccountVaultDelta::default();
    for asset in note_assets.iter() {
        vault_delta.add_asset(*asset).unwrap();
    }

    let mut storage_delta = AccountStorageDelta::new();
    if let Some((storage_update, tx_index)) = storage_update {
        if storage_update.storage_map_entries > 0
            && account.storage().get(&benchmark_storage_map_slot()).is_some()
        {
            let key_index = u32::try_from((tx_index % storage_update.storage_map_entries) + 1)
                .expect("storage map key fits into u32");
            storage_delta
                .set_map_item(
                    benchmark_storage_map_slot(),
                    StorageMapKey::from_index(key_index),
                    benchmark_storage_map_update_value(
                        storage_update.block_index,
                        tx_index,
                        key_index,
                    ),
                )
                .unwrap();
        }
    }

    AccountDelta::new(account.id(), storage_delta, vault_delta, ONE).unwrap()
}

/// Creates a transaction from the faucet that creates the given output notes. Updates the faucet
/// account to increase the issuance slot and it's nonce.
fn create_emit_note_tx(
    block_ref: &BlockHeader,
    faucet: &mut Account,
    output_notes: Vec<Note>,
) -> ProvenTransaction {
    let initial_account_hash = faucet.to_commitment();

    let token_config_slot = FungibleFaucet::token_config_slot();
    let slot = faucet.storage().get_item(token_config_slot).unwrap();
    faucet
        .storage_mut()
        .set_item(
            token_config_slot,
            [slot[0] + Felt::new_unchecked(10), slot[1], slot[2], slot[3]].into(),
        )
        .unwrap();

    faucet.increment_nonce(ONE).unwrap();

    let account_update = TxAccountUpdate::new(
        faucet.id(),
        initial_account_hash,
        faucet.to_commitment(),
        Word::empty(),
        AccountUpdateDetails::Private,
    )
    .unwrap();
    ProvenTransaction::new(
        account_update,
        Vec::<InputNoteCommitment>::new(),
        output_notes
            .into_iter()
            .map(|note| OutputNote::Public(PublicOutputNote::new(note).unwrap()))
            .collect::<Vec<OutputNote>>(),
        block_ref.block_num(),
        block_ref.commitment(),
        FungibleAsset::new(
            block_ref.fee_parameters().fee_faucet_id(),
            u64::from(block_ref.fee_parameters().verification_base_fee()),
        )
        .unwrap(),
        u32::MAX.into(),
        ExecutionProof::new_dummy(),
    )
    .unwrap()
}

/// Gets the batch inputs from the store and tracks the query time on the metrics.
async fn get_batch_inputs(
    store_state: &Arc<State>,
    block_ref: &BlockHeader,
    notes: &[Note],
    metrics: &mut SeedingMetrics,
) -> BatchInputs {
    let start = Instant::now();
    // Mark every note as unauthenticated, so that the store returns the inclusion proofs for all of
    // them
    let batch_inputs = store_state
        .get_batch_inputs(
            [block_ref.block_num()].into_iter().collect(),
            notes.iter().map(|note| note.id().as_word()).collect(),
        )
        .await
        .unwrap();
    metrics.add_get_batch_inputs(start.elapsed());
    batch_inputs
}

/// Gets the block inputs from the store and tracks the query time on the metrics.
async fn get_block_inputs(
    store_state: &Arc<State>,
    batches: &[ProvenBatch],
    metrics: &mut SeedingMetrics,
) -> BlockInputs {
    let start = Instant::now();
    let inputs = store_state
        .get_block_inputs(
            batches.iter().flat_map(ProvenBatch::updated_accounts).collect(),
            batches.iter().flat_map(ProvenBatch::created_nullifiers).collect(),
            batches
                .iter()
                .flat_map(|batch| {
                    batch
                        .input_notes()
                        .into_iter()
                        .filter_map(|note| note.header().map(|header| header.id().as_word()))
                })
                .collect(),
            batches.iter().map(ProvenBatch::reference_block_num).collect(),
        )
        .await
        .unwrap();
    let get_block_inputs_time = start.elapsed();
    metrics.add_get_block_inputs(get_block_inputs_time);
    inputs
}

/// Runs the store with the given data directory. Returns a tuple with:
/// - a gRPC client to access the store
/// - the URL of the store
///
/// The store uses a local prover.
pub async fn start_store(
    data_directory: PathBuf,
) -> (RpcClient<InterceptedService<Channel, OtelInterceptor>>, Url) {
    let rpc_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind store RPC gRPC endpoint");
    let store_addr = rpc_listener.local_addr().expect("Failed to get store RPC address");
    let dir = data_directory.clone();

    task::spawn(async move {
        Store {
            rpc_listener,
            mode: StoreMode::BlockProducer {
                block_prover_url: None,
                max_concurrent_proofs: miden_node_store::DEFAULT_MAX_CONCURRENT_PROOFS,
            },
            data_directory: dir,
            database_options: miden_node_store::DatabaseOptions::default(),
            grpc_options: GrpcOptionsInternal::bench(),
            storage_options: StorageOptions::bench(),
        }
        .serve()
        .await
        .expect("Failed to start serving store");
    });

    let channel = tonic::transport::Endpoint::try_from(format!("http://{store_addr}",))
        .unwrap()
        .connect()
        .await
        .expect("Failed to connect to store");

    let store_url = Url::parse(&format!("http://{store_addr}")).unwrap();
    (RpcClient::with_interceptor(channel, OtelInterceptor), store_url)
}

async fn load_state(data_directory: PathBuf) -> Arc<State> {
    let (termination_ask, _termination_signal) = tokio::sync::mpsc::channel(1);
    let (state, _) = State::load(&data_directory, StorageOptions::bench(), termination_ask)
        .await
        .expect("store state should load");
    Arc::new(state)
}
