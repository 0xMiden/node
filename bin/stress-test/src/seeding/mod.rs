use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use metrics::SeedingMetrics;
use miden_node_store::{BlockWriter, DataDirectory, GenesisState, State, WriterTask};
use miden_node_utils::clap::StorageOptions;
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountComponentMetadata,
    AccountId,
    AccountPatch,
    AccountStoragePatch,
    AccountType,
    AccountUpdateDetails,
    AccountVaultPatch,
    StorageMap,
    StorageMapKey,
    StorageMapPatch,
    StorageMapPatchEntries,
    StorageSlot,
    StorageSlotName,
    StorageSlotPatch,
};
use miden_protocol::asset::{Asset, AssetId, FungibleAsset, TokenSymbol};
use miden_protocol::batch::{BatchAccountUpdate, BatchId, ProvenBatch};
use miden_protocol::block::{
    BlockHeader,
    BlockInputs,
    BlockNumber,
    BlockSignatures,
    FeeParameters,
    ProposedBlock,
    SignedBlock,
    ValidatorConfig,
};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey as EcdsaSecretKey;
use miden_protocol::crypto::dsa::falcon512_poseidon2::{PublicKey, SecretKey};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{Note, NoteAssets, NoteId, NoteInclusionProof};
use miden_protocol::protocol_config::ProtocolConfig;
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
use miden_protocol::{ACCOUNT_UPDATE_MAX_SIZE, Felt, ONE, Word};
use miden_standards::account::auth::{Approver, AuthSingleSig};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{BurnPolicy, MintPolicy, TokenPolicyManager};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::P2idNote;
use rand::seq::SliceRandom;
use rand::{Rng, RngExt};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::prelude::ParallelSlice;
use tokio::fs;
use tokio::io::AsyncWriteExt;

mod metrics;
#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

const BATCHES_PER_BLOCK: usize = 16;
const TRANSACTIONS_PER_BATCH: usize = 16;
const ACCOUNT_UPDATES_PER_BLOCK: usize = BATCHES_PER_BLOCK * TRANSACTIONS_PER_BATCH - 1;
const STORAGE_MAP_ENTRY_SERIALIZED_SIZE: u64 = 64;
const ACCOUNT_UPDATE_SIZE_HEADROOM: u64 = 32 * 1024;

pub const ACCOUNTS_FILENAME: &str = "accounts.txt";

pub const BENCHMARK_STORAGE_MAP_SLOT_NAME: &str = "miden::mock::stress_test::map";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AccountBatch {
    public: usize,
    private: usize,
}

fn rounded_percentage(count: usize, percentage: u8) -> usize {
    let numerator = (count as u128) * u128::from(percentage) + 50;
    usize::try_from(numerator / 100).expect("percentage of usize fits into usize")
}

fn plan_account_batches(
    num_accounts: usize,
    public_accounts_percentage: u8,
    batch_capacity: usize,
) -> Vec<AccountBatch> {
    assert!(
        public_accounts_percentage <= 100,
        "public account percentage must be at most 100"
    );
    assert!(batch_capacity > 0, "account batch capacity must be non-zero");

    (0..num_accounts)
        .step_by(batch_capacity)
        .map(|start| {
            let end = start.saturating_add(batch_capacity).min(num_accounts);
            let public = rounded_percentage(end, public_accounts_percentage)
                - rounded_percentage(start, public_accounts_percentage);
            AccountBatch { public, private: end - start - public }
        })
        .collect()
}

fn account_update_may_exceed_protocol_limit(
    storage_map_entries: u32,
    vault_entries: usize,
) -> bool {
    let estimated_size = u64::from(storage_map_entries) * STORAGE_MAP_ENTRY_SERIALIZED_SIZE
        + u64::try_from(vault_entries).expect("vault entry count fits into u64")
            * STORAGE_MAP_ENTRY_SERIALIZED_SIZE
        + ACCOUNT_UPDATE_SIZE_HEADROOM;
    estimated_size > u64::from(ACCOUNT_UPDATE_MAX_SIZE)
}

// SEED STORE
// ================================================================================================

/// Seeds the store with a given number of accounts.
pub async fn seed_store(
    data_directory: PathBuf,
    num_accounts: usize,
    public_accounts_percentage: u8,
    storage_map_entries: u32,
    vault_entries: usize,
    account_update_blocks: usize,
) {
    seed_store_with_readers(
        data_directory,
        num_accounts,
        public_accounts_percentage,
        storage_map_entries,
        vault_entries,
        account_update_blocks,
        0,
    )
    .await;
}

/// Seeds the store while `readers` concurrent tasks measure read latency against the same state.
///
/// This is the mixed read/write benchmark: seeding provides a continuous block-application load,
/// and each reader loops `get_block_header` (latest header plus MMR proof) against the live state,
/// so the reported latencies capture how reads behave while blocks are being committed. With
/// `readers == 0` this is plain seeding.
#[expect(clippy::too_many_lines)]
pub async fn seed_store_with_readers(
    data_directory: PathBuf,
    num_accounts: usize,
    public_accounts_percentage: u8,
    storage_map_entries: u32,
    vault_entries: usize,
    account_update_blocks: usize,
    readers: usize,
) {
    let start = Instant::now();
    assert!(num_accounts > 0, "--num-accounts must be greater than zero");
    assert!(vault_entries > 0, "--vault-entries must be greater than zero");
    assert!(
        vault_entries <= NoteAssets::MAX_NUM_ASSETS,
        "--vault-entries must be at most {}",
        NoteAssets::MAX_NUM_ASSETS
    );
    if account_update_blocks > 0 {
        assert!(
            storage_map_entries > 0
                && rounded_percentage(num_accounts, public_accounts_percentage) > 0,
            "--account-update-blocks requires at least one public account and a non-empty benchmark storage map"
        );
    }

    // Recreate the data directory (it should be empty for store bootstrapping).
    //
    // Ignore the error since it will also error if it does not exist.
    let _ = fs_err::remove_dir_all(&data_directory);
    fs_err::create_dir_all(&data_directory).expect("created data directory");

    // Generate the faucet accounts and genesis state. Public account state which cannot fit into a
    // transaction account update is inserted at genesis so later partial updates can still exercise
    // normal block application.
    let benchmark_faucets = create_benchmark_faucets(vault_entries);
    let faucet = benchmark_faucets[0].clone();
    let asset_faucet_ids = benchmark_faucets.iter().map(Account::id).collect::<Vec<_>>();
    let num_public_accounts = rounded_percentage(num_accounts, public_accounts_percentage);
    let seed_public_accounts_at_genesis =
        account_update_may_exceed_protocol_limit(storage_map_entries, vault_entries);
    let genesis_account_key_pair = if seed_public_accounts_at_genesis {
        let coin_seed: [u64; 4] = rand::rng().random();
        let mut rng = RandomCoin::new(coin_seed.map(Felt::new_unchecked).into());
        Some(SecretKey::with_rng(&mut rng))
    } else {
        None
    };
    let genesis_benchmark_accounts =
        genesis_account_key_pair.as_ref().map_or_else(Vec::new, |key| {
            create_existing_benchmark_accounts(
                num_public_accounts,
                key,
                &asset_faucet_ids,
                storage_map_entries,
                vault_entries,
            )
        });
    let mut genesis_accounts = benchmark_faucets;
    genesis_accounts.extend(genesis_benchmark_accounts);
    let fee_params = FeeParameters::new(0);
    let signer = EcdsaSecretKey::new();
    let protocol_config = ProtocolConfig::current(AssetId::new_fungible(faucet.id()))
        .expect("benchmark faucet should define a valid protocol configuration");
    let genesis_state = GenesisState::new(
        genesis_accounts,
        fee_params,
        1,
        1,
        ValidatorConfig::new(vec![signer.public_key()], 1).unwrap(),
        protocol_config,
    );
    let genesis_block = genesis_state.into_block().expect("genesis block should be created");
    let genesis_header = genesis_block.inner().header().clone();
    State::bootstrap(genesis_block, &data_directory).expect("store should bootstrap");

    let (state, mut block_writer, writer_task) = load_state(data_directory.clone()).await;

    // Recreate the deterministic genesis benchmark accounts after bootstrapping instead of keeping
    // another copy of their potentially very large maps alive while the genesis block is built.
    let initial_accounts = genesis_account_key_pair.as_ref().map_or_else(Vec::new, |key| {
        create_existing_benchmark_accounts(
            num_public_accounts,
            key,
            &asset_faucet_ids,
            storage_map_entries,
            vault_entries,
        )
    });
    let account_batches = if seed_public_accounts_at_genesis {
        plan_account_batches(num_accounts - num_public_accounts, 0, ACCOUNT_UPDATES_PER_BLOCK)
    } else {
        plan_account_batches(num_accounts, public_accounts_percentage, ACCOUNT_UPDATES_PER_BLOCK)
    };

    // Spawn the benchmark readers before block generation starts so they observe the store under
    // continuous write load for the whole run.
    let stop_readers = Arc::new(AtomicBool::new(false));
    let reader_tasks: Vec<_> = (0..readers)
        .map(|_| {
            let state = Arc::clone(&state);
            let stop = Arc::clone(&stop_readers);
            tokio::spawn(async move { read_latest_header_until(&state, &stop).await })
        })
        .collect();

    // start generating blocks
    let accounts_filepath = data_directory.join(ACCOUNTS_FILENAME);
    let data_directory =
        miden_node_store::DataDirectory::load(data_directory).expect("data directory should exist");
    let metrics = Box::pin(generate_blocks(
        &state,
        account_batches,
        initial_accounts,
        if seed_public_accounts_at_genesis {
            u64::try_from(num_public_accounts).expect("public account count fits into u64")
        } else {
            0
        },
        faucet,
        genesis_header,
        &mut block_writer,
        data_directory,
        accounts_filepath,
        &signer,
        storage_map_entries,
        vault_entries,
        account_update_blocks,
        asset_faucet_ids,
    ))
    .await;

    // Stop the readers and report their latencies before stopping the store: they hold state
    // references, and the read phase should not include post-write quiescence.
    let write_load_elapsed = start.elapsed();
    stop_readers.store(true, Ordering::Relaxed);
    let mut read_latencies = Vec::new();
    for task in reader_tasks {
        read_latencies.extend(task.await.expect("benchmark reader should not panic"));
    }
    if readers > 0 {
        report_read_latencies(&read_latencies, readers, write_load_elapsed);
    }

    // Wait for the store to release its backing storage so callers can immediately re-load the
    // state from the same data directory.
    block_writer.stop(writer_task).await;

    println!("Total time: {:.3} seconds", start.elapsed().as_secs_f64());
    println!("{metrics}");
}

/// Loops `get_block_header` (latest header with MMR proof) against the state until `stop` is set,
/// returning the latency of every request.
///
/// The request combines an in-memory read (opening the latest block's MMR proof against the
/// snapshot's blockchain) with a database header lookup scoped to the snapshot's tip, so it
/// exercises the read path most exposed to concurrent block application.
async fn read_latest_header_until(
    state: &Arc<State>,
    stop: &AtomicBool,
) -> Vec<std::time::Duration> {
    let mut latencies = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        let start = Instant::now();
        let (header, proof) = state
            .view()
            .get_block_header(None, true)
            .await
            .expect("get_block_header should succeed during seeding");
        latencies.push(start.elapsed());
        assert!(
            header.is_some() && proof.is_some(),
            "latest block header and MMR proof should exist"
        );
    }
    latencies
}

/// Prints read-side statistics for the mixed read/write benchmark.
#[expect(clippy::cast_precision_loss)]
fn report_read_latencies(
    latencies: &[std::time::Duration],
    readers: usize,
    elapsed: std::time::Duration,
) {
    println!("Concurrent read statistics ({readers} readers during seeding):");
    println!("  Total reads: {}", latencies.len());
    println!("  Reads per second: {:.0}", latencies.len() as f64 / elapsed.as_secs_f64());
    crate::store::metrics::print_summary(latencies);
}

/// Generates batches of transactions to be inserted into the store.
///
/// Account-creation notes are emitted in batches of at most 255 and consumed in a subsequent
/// block. Optional benchmark updates likewise use separate note-emission and account-update
/// blocks so their insertion times can be reported independently.
#[expect(clippy::too_many_arguments)]
#[expect(clippy::too_many_lines)]
async fn generate_blocks(
    state: &State,
    account_batches: Vec<AccountBatch>,
    initial_accounts: Vec<Account>,
    first_account_index: u64,
    mut faucet: Account,
    genesis_header: BlockHeader,
    block_writer: &mut BlockWriter,
    data_directory: DataDirectory,
    accounts_filepath: PathBuf,
    signer: &EcdsaSecretKey,
    storage_map_entries: u32,
    vault_entries: usize,
    account_update_blocks: usize,
    asset_faucet_ids: Vec<AccountId>,
) -> SeedingMetrics {
    let mut metrics = SeedingMetrics::new(data_directory.database_path());

    let mut account_ids = initial_accounts.iter().map(Account::id).collect::<Vec<_>>();
    let mut account_states = initial_accounts
        .into_iter()
        .map(|account| (account.id(), account))
        .collect::<BTreeMap<_, _>>();

    let mut consume_notes_txs: Vec<ProvenTransaction> = vec![];
    let mut pending_consumed_accounts: Vec<Account> = vec![];

    // share random coin seed and key pair for all accounts to avoid key generation overhead
    let coin_seed: [u64; 4] = rand::rng().random();
    let rng = Arc::new(Mutex::new(RandomCoin::new(coin_seed.map(Felt::new_unchecked).into())));
    let key_pair = {
        let mut rng = rng.lock().unwrap();
        SecretKey::with_rng(&mut *rng)
    };

    let mut prev_block_header = genesis_header;
    let mut next_account_index = first_account_index;
    let mut pending_public_accounts = 0;

    for (batch_index, batch) in account_batches.into_iter().enumerate() {
        let mut block_txs = Vec::with_capacity(BATCHES_PER_BLOCK * TRANSACTIONS_PER_BATCH);

        // create public accounts and notes that mint assets for these accounts
        let (pub_accounts, pub_notes) = create_accounts_and_notes(
            batch.public,
            AccountType::Public,
            &key_pair,
            &rng,
            &asset_faucet_ids,
            next_account_index,
            storage_map_entries,
            vault_entries,
        );
        next_account_index += u64::try_from(batch.public).expect("account count fits into u64");

        // create private accounts and notes that mint assets for these accounts
        let (priv_accounts, priv_notes) = create_accounts_and_notes(
            batch.private,
            AccountType::Private,
            &key_pair,
            &rng,
            &asset_faucet_ids,
            next_account_index,
            storage_map_entries,
            vault_entries,
        );
        next_account_index += u64::try_from(batch.private).expect("account count fits into u64");

        let mut notes = pub_notes;
        notes.extend(priv_notes);
        let mut accounts = pub_accounts;
        accounts.extend(priv_accounts);
        account_ids.extend(accounts.iter().map(Account::id));
        // create the tx that creates the notes
        let emit_note_tx = create_emit_note_tx(&prev_block_header, &mut faucet, notes.clone());

        // collect all the txs
        let has_pending_account_creations = !consume_notes_txs.is_empty();
        block_txs.push(emit_note_tx);
        block_txs.extend(consume_notes_txs);

        // create the batches with [TRANSACTIONS_PER_BATCH] txs each
        let batches: Vec<ProvenBatch> = block_txs
            .par_chunks(TRANSACTIONS_PER_BATCH)
            .map(|txs| create_batch(txs, &prev_block_header))
            .collect();

        // create the block and send it to the store
        let block_inputs = get_block_inputs(state, &batches, &mut metrics).await;

        // update blocks
        let block_kind = if has_pending_account_creations {
            metrics::BlockKind::AccountCreation
        } else {
            metrics::BlockKind::AccountNoteEmission
        };
        prev_block_header = apply_block(
            batches,
            block_inputs,
            block_writer,
            &mut metrics,
            signer,
            block_kind,
            pending_public_accounts,
        )
        .await;
        account_states
            .extend(pending_consumed_accounts.into_iter().map(|account| (account.id(), account)));

        // create the consume notes txs to be used in the next block
        let note_inclusion_proofs =
            get_note_inclusion_proofs(state, &prev_block_header, &notes, &mut metrics).await;
        (pending_consumed_accounts, consume_notes_txs) = create_consume_note_txs(
            &prev_block_header,
            accounts,
            notes,
            &note_inclusion_proofs,
            None,
        );
        pending_public_accounts = batch.public;

        // track store size every 50 blocks
        if batch_index % 50 == 0 {
            metrics.record_store_size();
        }
    }

    // The creation pipeline emits notes in one block and consumes them in the next. Flush the final
    // set of consume transactions so `num_accounts` describes persisted accounts rather than merely
    // emitted account-creation notes.
    if !consume_notes_txs.is_empty() {
        let batches: Vec<ProvenBatch> = consume_notes_txs
            .par_chunks(TRANSACTIONS_PER_BATCH)
            .map(|txs| create_batch(txs, &prev_block_header))
            .collect();
        let block_inputs = get_block_inputs(state, &batches, &mut metrics).await;
        prev_block_header = apply_block(
            batches,
            block_inputs,
            block_writer,
            &mut metrics,
            signer,
            metrics::BlockKind::AccountCreation,
            pending_public_accounts,
        )
        .await;
        account_states
            .extend(pending_consumed_accounts.into_iter().map(|account| (account.id(), account)));
        metrics.record_store_size();
    }

    let update_note_faucet_ids =
        asset_faucet_ids.iter().take(vault_entries).copied().collect::<Vec<_>>();
    let mut random = rand::rng();
    for update_block_index in 0..account_update_blocks {
        let selected_account_ids = select_random_account_ids_for_update_notes(
            &account_states,
            ACCOUNT_UPDATES_PER_BLOCK,
            &mut random,
        );
        assert!(
            !selected_account_ids.is_empty(),
            "--account-update-blocks requires at least one public account with a benchmark storage map"
        );
        let notes = {
            let mut note_rng = rng.lock().unwrap();
            selected_account_ids
                .iter()
                .map(|account_id| create_note(&update_note_faucet_ids, *account_id, &mut note_rng))
                .collect::<Vec<_>>()
        };

        let emit_note_tx = create_emit_note_tx(&prev_block_header, &mut faucet, notes.clone());
        let batches = vec![create_batch(std::slice::from_ref(&emit_note_tx), &prev_block_header)];

        let block_inputs = get_block_inputs(state, &batches, &mut metrics).await;
        prev_block_header = apply_block(
            batches,
            block_inputs,
            block_writer,
            &mut metrics,
            signer,
            metrics::BlockKind::UpdateNoteEmission,
            0,
        )
        .await;

        let note_inclusion_proofs =
            get_note_inclusion_proofs(state, &prev_block_header, &notes, &mut metrics).await;
        let accounts = selected_account_ids
            .iter()
            .map(|account_id| {
                account_states
                    .remove(account_id)
                    .expect("selected update account should be present")
            })
            .collect::<Vec<_>>();
        let (updated_accounts, update_txs) = create_consume_note_txs(
            &prev_block_header,
            accounts,
            notes,
            &note_inclusion_proofs,
            Some(BenchmarkStorageUpdate {
                block_index: update_block_index,
                storage_map_entries,
            }),
        );
        let batches: Vec<ProvenBatch> = update_txs
            .par_chunks(TRANSACTIONS_PER_BATCH)
            .map(|txs| create_batch(txs, &prev_block_header))
            .collect();
        let block_inputs = get_block_inputs(state, &batches, &mut metrics).await;
        prev_block_header = apply_block(
            batches,
            block_inputs,
            block_writer,
            &mut metrics,
            signer,
            metrics::BlockKind::AccountUpdate,
            selected_account_ids.len(),
        )
        .await;
        account_states.extend(updated_accounts.into_iter().map(|account| (account.id(), account)));
        metrics.record_store_size();
    }

    metrics.record_store_size();

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
    block_writer: &mut BlockWriter,
    metrics: &mut SeedingMetrics,
    signer: &EcdsaSecretKey,
    block_kind: metrics::BlockKind,
    public_account_updates: usize,
) -> BlockHeader {
    let transaction_count = batches.iter().map(|batch| batch.transactions().as_slice().len()).sum();
    let proposed_block = ProposedBlock::new(block_inputs.clone(), batches).unwrap();
    let (header, body) = proposed_block.clone().into_header_and_body().unwrap();
    let block_size: usize = header.to_bytes().len() + body.to_bytes().len();
    let signature = signer.sign(header.commitment());
    let signatures = BlockSignatures::new(vec![signature]).unwrap();
    // SAFETY: The header, body, and signature are known to correspond to each other.
    let signed_block = SignedBlock::new_unchecked(header, body, signatures);
    let header = signed_block.header().clone();
    let ordered_batches = proposed_block.batches().clone();

    let start = Instant::now();
    block_writer
        .apply_block_with_proving_inputs(ordered_batches, block_inputs, signed_block)
        .await
        .unwrap();
    metrics.track_block_insertion(
        block_kind,
        start.elapsed(),
        block_size,
        transaction_count,
        public_account_updates,
    );

    header
}

// HELPER FUNCTIONS
// ================================================================================================

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
    first_account_index: u64,
    storage_map_entries: u32,
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
                first_account_index
                    + u64::try_from(account_index).expect("account index fits into u64"),
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
    let assets: Vec<Asset> = faucet_ids
        .iter()
        .map(|faucet_id| Asset::from(FungibleAsset::new(*faucet_id, 10).unwrap()))
        .collect();
    let sender = faucet_ids.first().copied().unwrap_or(target_id);
    P2idNote::builder()
        .sender(sender)
        .target(target_id)
        .assets(assets)
        .note_type(miden_protocol::note::NoteType::Public)
        .generate_serial_number(rng)
        .build()
        .expect("note creation failed")
        .into()
}

fn select_random_account_ids_for_update_notes<R: Rng + ?Sized>(
    account_states: &BTreeMap<AccountId, Account>,
    max_accounts: usize,
    rng: &mut R,
) -> Vec<AccountId> {
    let mut account_ids = account_states
        .values()
        .filter(|account| {
            account.is_public() && account.storage().get(&benchmark_storage_map_slot()).is_some()
        })
        .map(Account::id)
        .collect::<Vec<_>>();

    account_ids.shuffle(rng);
    account_ids.truncate(max_accounts);
    account_ids
}

#[derive(Clone, Copy)]
struct BenchmarkStorageUpdate {
    block_index: usize,
    storage_map_entries: u32,
}

fn benchmark_storage_map_update_value(block_index: usize, tx_index: u32, key_index: u32) -> Word {
    Word::from([
        Felt::ONE,
        Felt::from(u32::try_from(block_index + 1).expect("update block index fits into u32")),
        Felt::from(tx_index.checked_add(1).expect("transaction index fits into u32")),
        Felt::from(key_index),
    ])
}

fn update_benchmark_storage_map_entry(
    account: &mut Account,
    block_index: usize,
    tx_index: usize,
    storage_map_entries: u32,
) -> bool {
    if !account.is_public() || storage_map_entries == 0 {
        return false;
    }

    let tx_index = u32::try_from(tx_index).expect("transaction index fits into u32");
    let key_index = (tx_index % storage_map_entries) + 1;
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
    storage_map_entries: u32,
) -> Account {
    let init_seed: Vec<_> = index.to_be_bytes().into_iter().chain([0u8; 24]).collect();
    let mut builder = AccountBuilder::new(init_seed.try_into().unwrap())
        .account_type(account_type)
        .with_component(AuthSingleSig::new(Approver::new(
            public_key.into(),
            AuthScheme::Falcon512Poseidon2,
        )))
        .with_component(BasicWallet);

    if account_type == AccountType::Public && storage_map_entries > 0 {
        let entry_count =
            usize::try_from(storage_map_entries).expect("storage map entry count fits into usize");
        let entries = (0..entry_count).map(|index| {
            let i = u32::try_from(index + 1).expect("storage map entry index fits into u32");
            (
                StorageMapKey::from_index(i),
                Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::from(i)]),
            )
        });
        let storage_map = StorageMap::with_entries(entries).unwrap();
        let component_storage =
            vec![StorageSlot::with_map(benchmark_storage_map_slot(), storage_map)];
        let component_code = CodeBuilder::default()
            .compile_component_code(
                "benchmark::storage_map",
                "\
@account_procedure
pub proc noop
    push.0 drop
end",
            )
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

fn create_existing_benchmark_accounts(
    num_accounts: usize,
    key_pair: &SecretKey,
    asset_faucet_ids: &[AccountId],
    storage_map_entries: u32,
    vault_entries: usize,
) -> Vec<Account> {
    (0..num_accounts)
        .into_par_iter()
        .map(|account_index| {
            let mut account = create_account(
                key_pair.public_key(),
                u64::try_from(account_index).expect("account index fits into u64"),
                AccountType::Public,
                storage_map_entries,
            );
            for faucet_id in asset_faucet_ids.iter().take(vault_entries) {
                account
                    .vault_mut()
                    .add_asset(FungibleAsset::new(*faucet_id, 10).unwrap().into())
                    .unwrap();
            }
            account.increment_nonce(ONE).unwrap();
            account
        })
        .collect()
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
            TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::allow_all())
                .active_burn_policy(BurnPolicy::allow_all())
                .build(),
        )
        .with_component(AuthSingleSig::new(Approver::new(
            key_pair.public_key().into(),
            AuthScheme::Falcon512Poseidon2,
        )))
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
        miden_protocol::testing::dummy_execution_proof(),
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

    let (details, account_patch_commitment) = if account.is_public() {
        let account_patch = if is_new_account {
            AccountPatch::try_from(account.clone()).unwrap()
        } else {
            create_existing_account_patch(&account, input_note.note().assets(), storage_update)
        };
        let commitment = account_patch.to_commitment();
        (AccountUpdateDetails::Public(account_patch), commitment)
    } else {
        (AccountUpdateDetails::Private, Word::empty())
    };

    let account_update = TxAccountUpdate::new(
        account.id(),
        init_hash,
        account.to_commitment(),
        account_patch_commitment,
        details,
    )
    .unwrap();
    let transaction = ProvenTransaction::new(
        account_update,
        vec![InputNoteCommitment::from(input_note)],
        Vec::<OutputNote>::new(),
        block_ref.block_num(),
        block_ref.commitment(),
        u32::MAX.into(),
        miden_protocol::testing::dummy_execution_proof(),
    )
    .unwrap();

    (account, transaction)
}

fn create_existing_account_patch(
    account: &Account,
    note_assets: &NoteAssets,
    storage_update: Option<(BenchmarkStorageUpdate, usize)>,
) -> AccountPatch {
    let mut vault_patch = AccountVaultPatch::default();
    for asset in note_assets.iter() {
        let updated_asset = account
            .vault()
            .get(asset.id())
            .expect("note asset should be present in the account vault");
        vault_patch.insert_asset(updated_asset);
    }

    let storage_patch = match storage_update {
        Some((storage_update, tx_index))
            if storage_update.storage_map_entries > 0
                && account.storage().get(&benchmark_storage_map_slot()).is_some() =>
        {
            let tx_index = u32::try_from(tx_index).expect("transaction index fits into u32");
            let key_index = (tx_index % storage_update.storage_map_entries) + 1;
            let mut entries = StorageMapPatchEntries::new();
            entries.insert(
                StorageMapKey::from_index(key_index),
                benchmark_storage_map_update_value(storage_update.block_index, tx_index, key_index),
            );
            let map_patch = StorageMapPatch::Update { entries };
            AccountStoragePatch::from_raw(
                [(benchmark_storage_map_slot(), StorageSlotPatch::Map(map_patch))]
                    .into_iter()
                    .collect::<BTreeMap<_, _>>(),
            )
            .unwrap()
        },
        _ => AccountStoragePatch::new(),
    };

    AccountPatch::new(account.id(), storage_patch, vault_patch, None, Some(account.nonce()))
        .unwrap()
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
        u32::MAX.into(),
        miden_protocol::testing::dummy_execution_proof(),
    )
    .unwrap()
}

/// Gets note inclusion proofs from the store and tracks the query time on the metrics.
async fn get_note_inclusion_proofs(
    state: &State,
    block_ref: &BlockHeader,
    notes: &[Note],
    metrics: &mut SeedingMetrics,
) -> BTreeMap<NoteId, NoteInclusionProof> {
    let start = Instant::now();
    let note_inclusion_proofs = state
        .view()
        .get_note_inclusion_proofs(block_ref.block_num(), notes.iter().map(Note::id).collect())
        .await
        .unwrap();
    metrics.add_get_note_inclusion_proofs(start.elapsed());
    note_inclusion_proofs
}

/// Gets the block inputs from the store and tracks the query time on the metrics.
async fn get_block_inputs(
    state: &State,
    batches: &[ProvenBatch],
    metrics: &mut SeedingMetrics,
) -> BlockInputs {
    let start = Instant::now();
    let account_ids = batches.iter().flat_map(ProvenBatch::updated_accounts).collect::<Vec<_>>();
    let nullifiers = batches.iter().flat_map(ProvenBatch::created_nullifiers).collect::<Vec<_>>();
    let mut block_numbers: BTreeSet<_> =
        batches.iter().map(ProvenBatch::reference_block_num).collect();
    let note_ids = batches
        .iter()
        .flat_map(|batch| {
            batch
                .input_notes()
                .into_iter()
                .filter_map(|note| note.header().map(miden_protocol::note::NoteHeader::id))
        })
        .collect();
    let view = state.view();
    let reference_block = *view.tip();
    let note_inclusion_proofs =
        view.get_note_inclusion_proofs(reference_block, note_ids).await.unwrap();
    block_numbers.extend(note_inclusion_proofs.values().map(|proof| proof.location().block_num()));
    let partial_blockchain =
        view.get_block_inclusion_proofs(reference_block, block_numbers).await.unwrap();
    let reference_block_header = view
        .get_block_header(Some(reference_block), false)
        .await
        .unwrap()
        .0
        .expect("reference block header should exist");
    let state_witnesses = view.get_state_witnesses(&account_ids, &nullifiers);
    let inputs = BlockInputs::new(
        reference_block_header,
        partial_blockchain,
        state_witnesses.account_witnesses,
        state_witnesses.nullifier_witnesses,
        note_inclusion_proofs,
    );
    let get_block_inputs_time = start.elapsed();
    metrics.add_get_block_inputs(get_block_inputs_time);
    inputs
}

/// Loads the store state from the given data directory, detaching the block writer task.
///
/// Intended for benches that run until process exit and never need the storage released
/// deterministically; use [`load_state`] when the writer must be joined. The write capability is
/// leaked to keep the block writer alive for the process lifetime.
pub async fn start_store(data_directory: PathBuf) -> Arc<State> {
    let (state, block_writer, _writer_task) = load_state(data_directory).await;
    std::mem::forget(block_writer);
    state
}

/// Loads the store state and spawns its block writer, returning the write capability and the
/// writer's join handle.
///
/// The writer exits once the returned [`BlockWriter`] is dropped; awaiting the handle after that
/// guarantees the backing storage has been released.
async fn load_state(data_directory: PathBuf) -> (Arc<State>, BlockWriter, WriterTask) {
    let (state, block_writer, _proof_writer, writer_task) =
        State::load(&data_directory, StorageOptions::bench())
            .await
            .expect("store state should load")
            .start(CancellationToken::new());
    (state, block_writer, writer_task)
}
