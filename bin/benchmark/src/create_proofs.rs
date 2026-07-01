//! The `create-proofs` orchestrator and everything it needs to build the
//! proven-tx bundle locally:
//!
//! - `run` orchestrates the genesis fetch + faucet/wallet construction + mint phase + consume phase
//!   + final write-out to `./benchmark-proofs/`.
//! - `create_faucet` / `create_wallet` build the accounts the bench uses.
//! - `BenchmarkDataStore` is the in-memory `DataStore` impl that feeds the `TransactionExecutor`
//!   while we generate proofs locally.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountType,
    PartialAccount,
    StorageMapKey,
};
use miden_protocol::asset::{Asset, AssetVaultKey, AssetWitness, FungibleAsset, TokenSymbol};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{Note, NoteAttachments, NoteScript, NoteScriptRoot, PartialNote};
use miden_protocol::transaction::{
    AccountInputs,
    ExecutedTransaction,
    InputNote,
    InputNotes,
    PartialBlockchain,
    ProvenTransaction,
    TransactionArgs,
};
use miden_protocol::utils::serde::Serializable;
use miden_protocol::{Felt, MastForest, Word};
use miden_standards::account::auth::AuthSingleSig;
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::interface::{AccountInterface, AccountInterfaceExt};
use miden_standards::account::policies::{
    BurnPolicyConfig,
    MintPolicyConfig,
    PolicyRegistration,
    TokenPolicyManager,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::note::P2idNote;
use miden_tx::auth::BasicAuthenticator;
use miden_tx::{
    DataStore,
    DataStoreError,
    MastForestStore,
    TransactionExecutor,
    TransactionMastStore,
};
use rand::Rng;
use rayon::prelude::*;
use url::Url;

use crate::prover::BenchmarkProver;
use crate::rpc_state::{fetch_chain_tip_header, fetch_partial_blockchain};
use crate::summary::print_proving_summary;
use crate::{
    PROOFS_DIR,
    create_genesis_aware_rpc_client,
    get_genesis_header_request,
    write_to_file,
};

/// Maximum attempts to observe a stable chain tip.
const MAX_TIP_FETCH_ATTEMPTS: u32 = 10;

// CONSTANTS
// ================================================================================================

/// Maximum number of output notes packed into a single mint transaction.
///
/// 100 notes (~3.3 MB) keeps us comfortably under the 4 MiB gRPC limit with margin for the proof
/// growing slightly linearly in the note count.
const MAX_NOTES_PER_MINT_TX: usize = 100;

// PROVING TASK HELPERS
// ================================================================================================

/// Result of a single proving job: the proof attempt and the wall time it spent (which, for the
/// remote path, includes rate-limit and retry waits).
type ProveOutcome = (anyhow::Result<ProvenTransaction>, Duration);

/// Accumulates the proving jobs of one phase, dispatching them according to the prover's strategy:
///
/// - [`BenchmarkProver::supports_concurrent_proving`] true (remote): each job is spawned as a task
///   and awaited at [`collect`](Self::collect) time, so proving overlaps with later executions while
///   the prover's own rate limiter + in-flight cap bound the concurrency.
/// - false (local): each job runs inline and sequentially as it is submitted, since local proving is
///   single-process and memory-heavy.
enum ProofCollector {
    Sequential(Vec<ProveOutcome>),
    Concurrent(Vec<tokio::task::JoinHandle<ProveOutcome>>),
}

impl ProofCollector {
    fn new(prover: &BenchmarkProver, capacity: usize) -> Self {
        if prover.supports_concurrent_proving() {
            Self::Concurrent(Vec::with_capacity(capacity))
        } else {
            Self::Sequential(Vec::with_capacity(capacity))
        }
    }

    /// Submit one executed tx for proving. The remote path spawns a concurrent task and returns
    /// immediately; the local path proves inline now, blocking until the proof is done.
    async fn submit(&mut self, prover: &Arc<BenchmarkProver>, executed_tx: ExecutedTransaction) {
        match self {
            Self::Concurrent(tasks) => {
                let prover = Arc::clone(prover);
                tasks.push(tokio::spawn(async move {
                    let prove_t0 = Instant::now();
                    let result = prover.prove(executed_tx).await;
                    (result, prove_t0.elapsed())
                }));
            },
            Self::Sequential(outcomes) => {
                let prove_t0 = Instant::now();
                // Box the proof future so it doesn't inflate the caller's (`run`) future, which the
                // spawned remote path keeps off-stack via `tokio::spawn`.
                let result = Box::pin(prover.prove(executed_tx)).await;
                outcomes.push((result, prove_t0.elapsed()));
            },
        }
    }

    /// Gather every proof in submission order, returning them plus the summed per-job wall time. If
    /// any job fails (or a spawned task panics) we print the error and exit with a non-zero status.
    /// Proven txs later in the bundle reference earlier ones, so a single failure makes the bundle
    /// unusable anyway.
    async fn collect(self, label: &str) -> (Vec<ProvenTransaction>, Duration) {
        let outcomes = match self {
            Self::Sequential(outcomes) => outcomes,
            Self::Concurrent(tasks) => {
                let mut outcomes = Vec::with_capacity(tasks.len());
                for (i, handle) in tasks.into_iter().enumerate() {
                    outcomes.push(handle.await.unwrap_or_else(|err| {
                        eprintln!("{label} proving task {i} panicked: {err}");
                        std::process::exit(1);
                    }));
                }
                outcomes
            },
        };

        let mut proofs = Vec::with_capacity(outcomes.len());
        let mut total = Duration::ZERO;
        for (i, (result, elapsed)) in outcomes.into_iter().enumerate() {
            total += elapsed;
            match result {
                Ok(tx) => proofs.push(tx),
                Err(err) => {
                    eprintln!("{label} proving failed for tx {i}: {err:#}");
                    std::process::exit(1);
                },
            }
        }
        (proofs, total)
    }
}

// ORCHESTRATOR
// ================================================================================================

#[expect(
    clippy::too_many_lines,
    reason = "single linear orchestration of genesis fetch + mint phase + consume phase; \
              splitting would just shuffle locals (faucet, data_store, authenticator) around"
)]
pub(crate) async fn run(rpc_url: Url, num_transactions: u64, remote_prover_url: Option<String>) {
    let mut rpc_client = create_genesis_aware_rpc_client(&rpc_url, Duration::from_secs(10))
        .await
        .unwrap();

    println!("Fetching genesis block header from {rpc_url}...");
    let genesis_header_proto = rpc_client
        .get_block_header_by_number(get_genesis_header_request())
        .await
        .unwrap()
        .into_inner()
        .block_header
        .expect("RPC returned no block header");
    let genesis_header: BlockHeader = genesis_header_proto.try_into().unwrap();

    // The tip header and chain MMR come from separate RPC calls, so retry until they refer to the
    // same chain tip.
    let mut tip_state = None;
    for _ in 0..MAX_TIP_FETCH_ATTEMPTS {
        println!("Fetching chain tip header...");
        let ref_block_header = fetch_chain_tip_header(&mut rpc_client).await;
        let ref_block_num = ref_block_header.block_num();

        println!("Fetching chain MMR up to ref block...");
        let partial_blockchain =
            fetch_partial_blockchain(&mut rpc_client, ref_block_num.as_u32(), &genesis_header)
                .await;

        if partial_blockchain.chain_length() == ref_block_num {
            tip_state = Some((ref_block_header, partial_blockchain));
            break;
        }
    }
    let (ref_block_header, partial_blockchain) = tip_state.unwrap_or_else(|| {
        panic!(
            "failed to fetch a consistent tip header and chain MMR after \
             {MAX_TIP_FETCH_ATTEMPTS} attempts",
        )
    });
    let ref_block_num = ref_block_header.block_num();

    println!("Creating faucet...");
    let (mut faucet, faucet_secret_key) = create_faucet();

    let coin_seed: [u64; 4] = rand::rng().random();
    let mut seed_rng = RandomCoin::new(coin_seed.map(Felt::new_unchecked).into());
    let wallet_secret_key = SecretKey::with_rng(&mut seed_rng);
    let wallet_public_key = wallet_secret_key.public_key();

    println!("Creating {num_transactions} wallets in parallel...");
    let wallets: Vec<Account> = (0..num_transactions)
        .into_par_iter()
        .map(|index| create_wallet(&wallet_public_key, index))
        .collect();

    let mut data_store = BenchmarkDataStore::new(ref_block_header.clone(), partial_blockchain);
    data_store.add_account(faucet.clone());
    for wallet in &wallets {
        data_store.add_account(wallet.clone());
    }

    let authenticator = BasicAuthenticator::new(&[
        AuthSecretKey::Falcon512Poseidon2(faucet_secret_key),
        AuthSecretKey::Falcon512Poseidon2(wallet_secret_key),
    ]);

    let prover = Arc::new(match remote_prover_url {
        Some(url) => {
            println!("Using remote prover at {url} (rate-limited ramp from 1 to 10 req/s).");
            BenchmarkProver::remote(url)
        },
        None => BenchmarkProver::local(),
    });
    let faucet_id = faucet.id();

    // Mint phase: executions are sequential (each mutates the shared faucet), but proving runs
    // concurrently on the prover (under the rate limiter when remote). Each mint tx emits as many
    // output notes as execution allows (`MAX_NOTES_PER_MINT_TX`), one per destination wallet, so
    // the sequential phase shrinks from `num_transactions` txs to `ceil(num_transactions /
    // MAX_NOTES_PER_MINT_TX)` while still producing exactly one note per wallet for the consume
    // phase to spend.
    let num_mint_txs = (num_transactions as usize).div_ceil(MAX_NOTES_PER_MINT_TX);
    println!(
        "Executing {num_mint_txs} mint transactions (sequential, up to {MAX_NOTES_PER_MINT_TX} \
         notes each, {num_transactions} notes total)..."
    );
    let mut mint_proofs = ProofCollector::new(&prover, num_mint_txs);
    let mut mint_tx_inputs: Vec<Vec<u8>> = Vec::with_capacity(num_mint_txs);
    let mut mint_notes: Vec<Note> = Vec::with_capacity(num_transactions as usize);
    let mint_phase_start = Instant::now();
    let mut mint_exec_total = Duration::ZERO;

    for (mint_tx_index, wallet_chunk) in wallets.chunks(MAX_NOTES_PER_MINT_TX).enumerate() {
        // One P2ID note per wallet in this chunk; they all become output notes of a single mint tx.
        let notes: Vec<Note> = wallet_chunk
            .iter()
            .map(|wallet| {
                let asset = Asset::Fungible(FungibleAsset::new(faucet_id, 10).unwrap());
                P2idNote::create(
                    faucet_id,
                    wallet.id(),
                    vec![asset],
                    miden_protocol::note::NoteType::Public,
                    NoteAttachments::empty(),
                    &mut seed_rng,
                )
                .expect("note creation failed")
            })
            .collect();

        let partial_notes: Vec<PartialNote> = notes.iter().map(|n| n.clone().into()).collect();
        let account_interface = AccountInterface::from_account(&faucet);
        let script = account_interface
            .build_send_notes_script(&partial_notes, None)
            .expect("failed to build mint send-notes script");

        let mut tx_args = TransactionArgs::default().with_tx_script(script);
        for note in &notes {
            tx_args.add_output_note_recipient(Box::new(note.recipient().clone()));
        }

        let executor = TransactionExecutor::new(&data_store).with_authenticator(&authenticator);

        let exec_t0 = Instant::now();
        let executed_tx = Box::pin(executor.execute_transaction(
            faucet_id,
            ref_block_num,
            InputNotes::default(),
            tx_args,
        ))
        .await
        .expect("failed to execute mint transaction");
        mint_exec_total += exec_t0.elapsed();

        let tx_inputs_bytes = executed_tx.tx_inputs().to_bytes();
        let delta = executed_tx.account_delta().clone();

        // Evolve the faucet state for the next iteration before we hand the executed tx off for
        // proving. The first mint of a never-before-seen account produces a full-state delta
        // (because the delta carries the freshly deployed code); subsequent mints produce
        // partial-state deltas that can be applied incrementally.
        if delta.is_full_state() {
            faucet = Account::try_from(&delta)
                .expect("failed to materialize faucet from full-state delta");
        } else {
            faucet.apply_delta(&delta).expect("failed to apply faucet delta");
        }
        data_store.add_account(faucet.clone());

        mint_proofs.submit(&prover, executed_tx).await;
        mint_tx_inputs.push(tx_inputs_bytes);
        mint_notes.extend(notes);

        println!(
            "  executed {} / {num_mint_txs} mint txs ({} / {num_transactions} notes)",
            mint_tx_index + 1,
            mint_notes.len(),
        );
    }

    println!("Awaiting {num_mint_txs} mint proofs...");
    let (mint_txs, mint_prove_total) = mint_proofs.collect("mint").await;
    let mint_phase_elapsed = mint_phase_start.elapsed();
    print_proving_summary(
        "Mint",
        num_mint_txs as u64,
        mint_phase_elapsed,
        mint_exec_total,
        mint_prove_total,
    );

    // Consume phase — same shape: sequential executions; proving dispatched per the prover
    // strategy.
    println!("Executing {num_transactions} consume transactions (sequential)...");
    let mut consume_proofs = ProofCollector::new(&prover, num_transactions as usize);
    let mut consume_tx_inputs: Vec<Vec<u8>> = Vec::with_capacity(num_transactions as usize);
    let consume_phase_start = Instant::now();
    let mut consume_exec_total = Duration::ZERO;

    for index in 0..num_transactions {
        let wallet_id = wallets[index as usize].id();
        let note = mint_notes[index as usize].clone();
        let input_note = InputNote::Unauthenticated { note };
        let input_notes =
            InputNotes::new(vec![input_note]).expect("failed to construct input notes for consume");

        let executor = TransactionExecutor::new(&data_store).with_authenticator(&authenticator);

        let exec_t0 = Instant::now();
        let executed_tx = Box::pin(executor.execute_transaction(
            wallet_id,
            ref_block_num,
            input_notes,
            TransactionArgs::default(),
        ))
        .await
        .expect("failed to execute consume transaction");
        consume_exec_total += exec_t0.elapsed();

        let tx_inputs_bytes = executed_tx.tx_inputs().to_bytes();

        consume_proofs.submit(&prover, executed_tx).await;
        consume_tx_inputs.push(tx_inputs_bytes);

        if (index + 1) % 10 == 0 || index + 1 == num_transactions {
            println!("  executed {} / {num_transactions} consume txs", index + 1);
        }
    }

    println!("Awaiting {num_transactions} consume proofs...");
    let (consume_txs, consume_prove_total) = consume_proofs.collect("consume").await;
    let consume_phase_elapsed = consume_phase_start.elapsed();
    print_proving_summary(
        "Consume",
        num_transactions,
        consume_phase_elapsed,
        consume_exec_total,
        consume_prove_total,
    );

    let out_dir = PathBuf::from(PROOFS_DIR);
    println!("Writing proofs to {}/", out_dir.display());
    fs_err::create_dir_all(&out_dir).unwrap();
    write_to_file(&out_dir.join("mint_txs.bin"), &mint_txs);
    write_to_file(&out_dir.join("mint_tx_inputs.bin"), &mint_tx_inputs);
    write_to_file(&out_dir.join("consume_txs.bin"), &consume_txs);
    write_to_file(&out_dir.join("consume_tx_inputs.bin"), &consume_tx_inputs);
    println!("Done.");
}

// ACCOUNT BUILDERS
// ================================================================================================

/// Creates a new faucet account and returns it alongside its secret key.
fn create_faucet() -> (Account, SecretKey) {
    let coin_seed: [u64; 4] = rand::rng().random();
    let mut rng = RandomCoin::new(coin_seed.map(Felt::new_unchecked).into());
    let key_pair = SecretKey::with_rng(&mut rng);
    let init_seed = [0_u8; 32];

    let fungible_faucet: AccountComponent = FungibleFaucet::builder()
        .name(TokenName::new("BENCHMARK").unwrap())
        .symbol(TokenSymbol::new("BCM").unwrap())
        .decimals(2)
        .max_supply(FungibleAsset::MAX_AMOUNT)
        .build()
        .unwrap()
        .into();

    let faucet = AccountBuilder::new(init_seed)
        .account_type(AccountType::Private)
        .with_component(fungible_faucet)
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
        .unwrap();
    (faucet, key_pair)
}

/// Creates a new wallet account with the given public key, using `index` to vary the init seed so
/// each wallet ends up with a distinct account ID.
fn create_wallet(
    public_key: &miden_protocol::crypto::dsa::falcon512_poseidon2::PublicKey,
    index: u64,
) -> Account {
    let init_seed: Vec<_> = index.to_be_bytes().into_iter().chain([0u8; 24]).collect();
    AccountBuilder::new(init_seed.try_into().unwrap())
        .account_type(AccountType::Private)
        .with_auth_component(AuthSingleSig::new(
            public_key.clone().into(),
            AuthScheme::Falcon512Poseidon2,
        ))
        .with_component(BasicWallet)
        .build()
        .unwrap()
}

// BENCHMARK DATA STORE
// ================================================================================================

/// In-memory `DataStore` impl used to feed the [`TransactionExecutor`] when generating real proofs
/// locally. Modelled on the network-monitor's `MonitorDataStore`.
struct BenchmarkDataStore {
    accounts: HashMap<AccountId, Account>,
    block_header: BlockHeader,
    partial_block_chain: PartialBlockchain,
    mast_store: TransactionMastStore,
}

impl BenchmarkDataStore {
    fn new(block_header: BlockHeader, partial_block_chain: PartialBlockchain) -> Self {
        Self {
            accounts: HashMap::new(),
            block_header,
            partial_block_chain,
            mast_store: TransactionMastStore::new(),
        }
    }

    fn add_account(&mut self, account: Account) {
        self.mast_store.load_account_code(account.code());
        self.accounts.insert(account.id(), account);
    }

    fn get_account(&self, account_id: AccountId) -> Result<&Account, DataStoreError> {
        self.accounts.get(&account_id).ok_or_else(|| DataStoreError::Other {
            error_msg: "unknown account".into(),
            source: None,
        })
    }
}

impl DataStore for BenchmarkDataStore {
    async fn get_transaction_inputs(
        &self,
        account_id: AccountId,
        _block_refs: BTreeSet<BlockNumber>,
    ) -> Result<(PartialAccount, BlockHeader, PartialBlockchain), DataStoreError> {
        let account = self.get_account(account_id)?;
        let partial_account = PartialAccount::from(account);
        Ok((partial_account, self.block_header.clone(), self.partial_block_chain.clone()))
    }

    async fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        map_root: Word,
        map_key: StorageMapKey,
    ) -> Result<miden_protocol::account::StorageMapWitness, DataStoreError> {
        let account = self.get_account(account_id)?;
        for slot in account.storage().slots() {
            if let miden_protocol::account::StorageSlotContent::Map(map) = slot.content() {
                if map.root() == map_root {
                    return Ok(map.open(&map_key));
                }
            }
        }
        Err(DataStoreError::Other {
            error_msg: format!("no storage map with the requested root in account {account_id}")
                .into(),
            source: None,
        })
    }

    async fn get_foreign_account_inputs(
        &self,
        _foreign_account_id: AccountId,
        _ref_block: BlockNumber,
    ) -> Result<AccountInputs, DataStoreError> {
        unimplemented!("foreign account inputs are not needed for the benchmark")
    }

    async fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        vault_root: Word,
        vault_keys: BTreeSet<AssetVaultKey>,
    ) -> Result<Vec<AssetWitness>, DataStoreError> {
        let account = self.get_account(account_id)?;

        if account.vault().root() != vault_root {
            return Err(DataStoreError::Other {
                error_msg: "vault root mismatch".into(),
                source: None,
            });
        }

        Result::<Vec<_>, _>::from_iter(vault_keys.into_iter().map(|vault_key| {
            AssetWitness::new(account.vault().open(vault_key).into()).map_err(|err| {
                DataStoreError::Other {
                    error_msg: "failed to open vault asset tree".into(),
                    source: Some(Box::new(err)),
                }
            })
        }))
    }

    async fn get_note_script(
        &self,
        _script_root: NoteScriptRoot,
    ) -> Result<Option<NoteScript>, DataStoreError> {
        Ok(None)
    }
}

impl MastForestStore for BenchmarkDataStore {
    fn get(&self, procedure_hash: &Word) -> Option<Arc<MastForest>> {
        self.mast_store.get(procedure_hash)
    }
}
