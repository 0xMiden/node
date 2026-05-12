//! Runs benchmarks

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use miden_node_proto::clients::{Builder, RpcClient};
use miden_node_proto::generated as proto;
use miden_node_proto::generated::rpc::BlockHeaderByNumberRequest;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountStorageMode,
    AccountType,
    PartialAccount,
    StorageMapKey,
};
use miden_protocol::asset::{Asset, AssetVaultKey, AssetWitness, FungibleAsset, TokenSymbol};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
use miden_protocol::crypto::merkle::mmr::{MmrPeaks, PartialMmr};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_protocol::transaction::{
    AccountInputs,
    InputNote,
    InputNotes,
    PartialBlockchain,
    ProvenTransaction,
    TransactionArgs,
};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::{Felt, MastForest, Word};
use miden_standards::account::auth::AuthSingleSig;
use miden_standards::account::faucets::BasicFungibleFaucet;
use miden_standards::account::interface::{AccountInterface, AccountInterfaceExt};
use miden_standards::account::metadata::{FungibleTokenMetadata, TokenName};
use miden_standards::account::policies::{
    BurnPolicyConfig,
    MintPolicyConfig,
    PolicyAuthority,
    TokenPolicyManager,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::note::P2idNote;
use miden_tx::auth::BasicAuthenticator;
use miden_tx::{
    DataStore,
    DataStoreError,
    LocalTransactionProver,
    MastForestStore,
    TransactionExecutor,
    TransactionMastStore,
};
use rand::Rng;
use rayon::prelude::*;
use tokio::sync::Semaphore;
use url::Url;

const PROOFS_DIR: &str = "./benchmark-proofs";

// COMMANDS
// ================================================================================================

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    CreateProofs {
        /// RPC endpoint of the target miden node — used to discover the
        /// genesis commitment that the generated proofs are bound to. Must
        /// match the node you intend to submit the proofs against.
        #[arg(long, default_value = "http://127.0.0.1:57291")]
        rpc_url: Url,
        /// Number of mint + consume transaction pairs to generate. Each
        /// pair takes seconds of real STARK proving, so start small.
        #[arg(long, default_value_t = 10)]
        num_transactions: u64,
    },
    RunBenchmark {
        /// RPC endpoint of the target miden node.
        #[arg(long, default_value = "http://127.0.0.1:57291")]
        rpc_url: Url,
        /// Number of concurrent submission tasks.
        #[arg(long, default_value_t = 32)]
        concurrency: usize,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    cli.run().await;
}

impl Cli {
    async fn run(self) {
        match self.command {
            Command::CreateProofs { rpc_url, num_transactions } => {
                create_proofs(rpc_url, num_transactions).await
            },
            Command::RunBenchmark { rpc_url, concurrency } => {
                run_benchmark(rpc_url, concurrency).await
            },
        }
    }
}

async fn create_proofs(rpc_url: Url, num_transactions: u64) {
    let mut rpc_client =
        create_genesis_aware_rpc_client(&rpc_url, Duration::from_secs(10)).await.unwrap();

    println!("Fetching genesis block header from {rpc_url}...");
    let genesis_header_proto = rpc_client
        .get_block_header_by_number(get_genesis_header_request())
        .await
        .unwrap()
        .into_inner()
        .block_header
        .expect("RPC returned no block header");
    let genesis_header: BlockHeader = genesis_header_proto.try_into().unwrap();

    println!("Creating faucet...");
    let (mut faucet, faucet_secret_key) = create_faucet();

    let coin_seed: [u64; 4] = rand::rng().random();
    let mut seed_rng = RandomCoin::new(coin_seed.map(Felt::new).into());
    let wallet_secret_key = SecretKey::with_rng(&mut seed_rng);
    let wallet_public_key = wallet_secret_key.public_key();

    println!("Creating {num_transactions} wallets in parallel...");
    let wallets: Vec<Account> = (0..num_transactions)
        .into_par_iter()
        .map(|index| create_wallet(wallet_public_key.clone(), index))
        .collect();

    let genesis_chain_mmr =
        PartialBlockchain::new(PartialMmr::from_peaks(MmrPeaks::default()), Vec::new())
            .expect("failed to create empty chain MMR");

    let mut data_store = BenchmarkDataStore::new(genesis_header.clone(), genesis_chain_mmr);
    data_store.add_account(faucet.clone());
    for wallet in &wallets {
        data_store.add_account(wallet.clone());
    }

    let authenticator = BasicAuthenticator::new(&[
        AuthSecretKey::Falcon512Poseidon2(faucet_secret_key),
        AuthSecretKey::Falcon512Poseidon2(wallet_secret_key),
    ]);

    let prover = LocalTransactionProver::default();
    let faucet_id = faucet.id();

    // Mint phase — sequential because each mint mutates the faucet.
    println!("Proving {num_transactions} mint transactions (sequential)...");
    let mut mint_txs: Vec<ProvenTransaction> = Vec::with_capacity(num_transactions as usize);
    let mut mint_tx_inputs: Vec<Vec<u8>> = Vec::with_capacity(num_transactions as usize);
    let mut mint_notes: Vec<Note> = Vec::with_capacity(num_transactions as usize);

    for index in 0..num_transactions {
        let wallet_id = wallets[index as usize].id();
        let note = {
            let asset = Asset::Fungible(FungibleAsset::new(faucet_id, 10).unwrap());
            P2idNote::create(
                faucet_id,
                wallet_id,
                vec![asset],
                miden_protocol::note::NoteType::Public,
                miden_protocol::note::NoteAttachment::default(),
                &mut seed_rng,
            )
            .expect("note creation failed")
        };

        let account_interface = AccountInterface::from_account(&faucet);
        let script = account_interface
            .build_send_notes_script(&[note.clone().into()], None)
            .expect("failed to build mint send-notes script");

        let mut tx_args = TransactionArgs::default().with_tx_script(script);
        tx_args.add_output_note_recipient(Box::new(note.recipient().clone()));

        let executor =
            TransactionExecutor::new(&data_store).with_authenticator(&authenticator);

        let executed_tx = Box::pin(executor.execute_transaction(
            faucet_id,
            genesis_header.block_num(),
            InputNotes::default(),
            tx_args,
        ))
        .await
        .expect("failed to execute mint transaction");

        let tx_inputs_bytes = executed_tx.tx_inputs().to_bytes();
        let delta = executed_tx.account_delta().clone();

        let proven_tx = prover
            .prove(executed_tx)
            .await
            .expect("failed to prove mint transaction");

        // Evolve the faucet state for the next iteration. The first mint of a
        // never-before-seen account produces a full-state delta (because the
        // delta carries the freshly deployed code); subsequent mints produce
        // partial-state deltas that can be applied incrementally.
        if delta.is_full_state() {
            faucet = Account::try_from(&delta)
                .expect("failed to materialize faucet from full-state delta");
        } else {
            faucet
                .apply_delta(&delta)
                .expect("failed to apply faucet delta");
        }
        data_store.update_account(faucet.clone());

        mint_txs.push(proven_tx);
        mint_tx_inputs.push(tx_inputs_bytes);
        mint_notes.push(note);

        if (index + 1) % 10 == 0 || index + 1 == num_transactions {
            println!("  proved {} / {num_transactions} mint txs", index + 1);
        }
    }

    // Consume phase — also sequential for now (each tx is one wallet, independent
    // wallets, so this could be parallelized later with bounded concurrency).
    println!("Proving {num_transactions} consume transactions (sequential)...");
    let mut consume_txs: Vec<ProvenTransaction> = Vec::with_capacity(num_transactions as usize);
    let mut consume_tx_inputs: Vec<Vec<u8>> = Vec::with_capacity(num_transactions as usize);

    for index in 0..num_transactions {
        let wallet_id = wallets[index as usize].id();
        let note = mint_notes[index as usize].clone();
        let input_note = InputNote::Unauthenticated { note };
        let input_notes = InputNotes::new(vec![input_note])
            .expect("failed to construct input notes for consume");

        let executor =
            TransactionExecutor::new(&data_store).with_authenticator(&authenticator);

        let executed_tx = Box::pin(executor.execute_transaction(
            wallet_id,
            genesis_header.block_num(),
            input_notes,
            TransactionArgs::default(),
        ))
        .await
        .expect("failed to execute consume transaction");

        let tx_inputs_bytes = executed_tx.tx_inputs().to_bytes();

        let proven_tx = prover
            .prove(executed_tx)
            .await
            .expect("failed to prove consume transaction");

        consume_txs.push(proven_tx);
        consume_tx_inputs.push(tx_inputs_bytes);

        if (index + 1) % 10 == 0 || index + 1 == num_transactions {
            println!("  proved {} / {num_transactions} consume txs", index + 1);
        }
    }

    let out_dir = PathBuf::from(PROOFS_DIR);
    println!("Writing proofs to {}/", out_dir.display());
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(out_dir.join("faucet.bin"), faucet.to_bytes()).unwrap();
    std::fs::write(out_dir.join("wallets.bin"), wallets.to_bytes()).unwrap();
    std::fs::write(out_dir.join("mint_txs.bin"), mint_txs.to_bytes()).unwrap();
    std::fs::write(out_dir.join("mint_tx_inputs.bin"), mint_tx_inputs.to_bytes()).unwrap();
    std::fs::write(out_dir.join("consume_txs.bin"), consume_txs.to_bytes()).unwrap();
    std::fs::write(out_dir.join("consume_tx_inputs.bin"), consume_tx_inputs.to_bytes()).unwrap();
    println!("Done.");
}

async fn run_benchmark(rpc_url: Url, concurrency: usize) {
    let in_dir = PathBuf::from(PROOFS_DIR);

    println!("Loading mint txs from {}", in_dir.join("mint_txs.bin").display());
    let mint_txs = read_proven_txs(&in_dir.join("mint_txs.bin"));
    let mint_tx_inputs = read_tx_inputs(&in_dir.join("mint_tx_inputs.bin"));
    assert_eq!(mint_txs.len(), mint_tx_inputs.len(), "mint tx/inputs length mismatch");

    println!("Loading consume txs from {}", in_dir.join("consume_txs.bin").display());
    let consume_txs = read_proven_txs(&in_dir.join("consume_txs.bin"));
    let consume_tx_inputs = read_tx_inputs(&in_dir.join("consume_tx_inputs.bin"));
    assert_eq!(consume_txs.len(), consume_tx_inputs.len(), "consume tx/inputs length mismatch");

    println!("Connecting to {rpc_url}...");
    let rpc_client = create_genesis_aware_rpc_client(&rpc_url, Duration::from_secs(30))
        .await
        .expect("failed to create RPC client");

    let h_start = current_block_height(rpc_client.clone()).await;
    println!("Chain height at start: {h_start}");

    println!(
        "Submitting {} mint txs sequentially (each one mutates the shared faucet, so the \
         submits must be serialized for the mempool to chain them)...",
        mint_txs.len()
    );
    let (mint_ok, mint_err, mint_elapsed) =
        submit_sequential(rpc_client.clone(), mint_txs, mint_tx_inputs).await;
    println!(
        "  mint: ok={mint_ok} err={mint_err} in {:.1}s ({:.2} tx/s)",
        mint_elapsed.as_secs_f64(),
        mint_ok as f64 / mint_elapsed.as_secs_f64()
    );

    println!("Submitting {} consume txs with concurrency={concurrency}...", consume_txs.len());
    let (consume_ok, consume_err, consume_elapsed) =
        submit_all(rpc_client.clone(), consume_txs, consume_tx_inputs, concurrency).await;
    println!(
        "  consume: ok={consume_ok} err={consume_err} in {:.1}s ({:.0} tx/s)",
        consume_elapsed.as_secs_f64(),
        consume_ok as f64 / consume_elapsed.as_secs_f64()
    );

    println!("Waiting 3 blocks for the last submissions to land...");
    let h_final = wait_for_n_blocks(rpc_client.clone(), 3).await;

    let total_submitted = mint_ok + consume_ok;
    let total_submission_secs = (mint_elapsed + consume_elapsed).as_secs_f64();
    println!();
    println!("=== Summary ===");
    println!("Chain height: {h_start} -> {h_final} ({} blocks)", h_final - h_start);
    println!("Total successful submissions: {total_submitted}");
    println!("Total submission time: {:.1}s", total_submission_secs);
    println!("Submission TPS: {:.0}", total_submitted as f64 / total_submission_secs);
}

fn read_proven_txs(path: &std::path::Path) -> Vec<ProvenTransaction> {
    let bytes = std::fs::read(path).unwrap_or_else(|_| {
        panic!(
            "failed to read {} — run `create-proofs` first",
            path.display()
        )
    });
    Vec::<ProvenTransaction>::read_from_bytes(&bytes)
        .unwrap_or_else(|_| panic!("failed to deserialize {}", path.display()))
}

fn read_tx_inputs(path: &std::path::Path) -> Vec<Vec<u8>> {
    let bytes = std::fs::read(path).unwrap_or_else(|_| {
        panic!(
            "failed to read {} — run `create-proofs` first",
            path.display()
        )
    });
    Vec::<Vec<u8>>::read_from_bytes(&bytes)
        .unwrap_or_else(|_| panic!("failed to deserialize {}", path.display()))
}

async fn submit_all(
    client: RpcClient,
    txs: Vec<ProvenTransaction>,
    tx_inputs: Vec<Vec<u8>>,
    concurrency: usize,
) -> (u64, u64, Duration) {
    /// How many distinct error messages to surface to the console.
    const MAX_ERRORS_TO_PRINT: u64 = 5;

    let start = Instant::now();
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let ok = Arc::new(AtomicU64::new(0));
    let err = Arc::new(AtomicU64::new(0));
    let printed = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::with_capacity(txs.len());
    for (i, (tx, inputs)) in txs.into_iter().zip(tx_inputs.into_iter()).enumerate() {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let mut client = client.clone();
        let ok = ok.clone();
        let err = err.clone();
        let printed = printed.clone();
        handles.push(tokio::spawn(async move {
            let request = proto::transaction::ProvenTransaction {
                transaction: tx.to_bytes(),
                transaction_inputs: Some(inputs),
            };
            match client.submit_proven_transaction(request).await {
                Ok(_) => {
                    ok.fetch_add(1, Ordering::Relaxed);
                },
                Err(status) => {
                    err.fetch_add(1, Ordering::Relaxed);
                    if printed.fetch_add(1, Ordering::Relaxed) < MAX_ERRORS_TO_PRINT {
                        eprintln!(
                            "  tx idx {i} failed: code={:?} message={}",
                            status.code(),
                            status.message()
                        );
                    }
                },
            }
            drop(permit);
        }));
    }
    for h in handles {
        let _ = h.await;
    }

    (ok.load(Ordering::Relaxed), err.load(Ordering::Relaxed), start.elapsed())
}

/// Submit txs one at a time, awaiting each RPC response before sending the
/// next. Used for the mint phase, where every tx mutates the shared faucet
/// and therefore must arrive at the mempool in order — the block-producer's
/// mempool will reject out-of-order submissions but happily chains in-order
/// ones against its own pending state, so we only need to serialize the
/// `submit_proven_transaction` calls themselves, not wait for block
/// inclusion in between.
async fn submit_sequential(
    client: RpcClient,
    txs: Vec<ProvenTransaction>,
    tx_inputs: Vec<Vec<u8>>,
) -> (u64, u64, Duration) {
    let start = Instant::now();
    let mut ok: u64 = 0;
    let mut err: u64 = 0;
    let total = txs.len();

    for (i, (tx, inputs)) in txs.into_iter().zip(tx_inputs.into_iter()).enumerate() {
        let request = proto::transaction::ProvenTransaction {
            transaction: tx.to_bytes(),
            transaction_inputs: Some(inputs),
        };

        let mut submit_client = client.clone();
        match submit_client.submit_proven_transaction(request).await {
            Ok(_) => ok += 1,
            Err(e) => {
                err += 1;
                eprintln!("  tx {} / {total} failed: {}", i + 1, e);
            },
        }
    }

    println!("  submitted {total} (ok={ok} err={err})");
    (ok, err, start.elapsed())
}

async fn current_block_height(mut client: RpcClient) -> u32 {
    let response = client
        .get_block_header_by_number(BlockHeaderByNumberRequest {
            block_num: None,
            include_mmr_proof: None,
        })
        .await
        .expect("failed to fetch latest block header")
        .into_inner();
    let header: BlockHeader = response
        .block_header
        .expect("no block header in response")
        .try_into()
        .expect("failed to decode block header");
    header.block_num().as_u32()
}

/// Wait until the chain has advanced by `n` blocks past whatever the current
/// height is, then return. Used to give the block-producer time to include
/// in-flight submissions without falsely waiting forever (the node produces
/// empty blocks at a steady interval, so "no height change" never fires).
async fn wait_for_n_blocks(client: RpcClient, n: u32) -> u32 {
    let start_height = current_block_height(client.clone()).await;
    let target = start_height + n;
    let mut last = start_height;
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let h = current_block_height(client.clone()).await;
        if h != last {
            println!("  block height: {h}");
            last = h;
        }
        if h >= target {
            return h;
        }
    }
}

/// Create an RPC client configured with the correct genesis metadata in the
/// `Accept` header so that write RPCs such as `SubmitProvenTransaction` are
/// accepted by the node.
pub async fn create_genesis_aware_rpc_client(
    rpc_url: &Url,
    timeout: Duration,
) -> Result<RpcClient> {
    let use_tls = rpc_url.scheme() == "https";

    let tls_stage = Builder::new(rpc_url.clone());
    let timeout_stage = if use_tls {
        tls_stage.with_tls().context("Failed to configure TLS for RPC client")?
    } else {
        tls_stage.without_tls()
    };
    let mut rpc: RpcClient = timeout_stage
        .with_timeout(timeout)
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect()
        .await
        .context("Failed to create RPC client for genesis discovery")?;

    let response = rpc
        .get_block_header_by_number(get_genesis_header_request())
        .await
        .context("Failed to get genesis block header from RPC")?
        .into_inner();

    let genesis_block_header = response
        .block_header
        .ok_or_else(|| anyhow::anyhow!("No block header in response"))?;

    let genesis_header: BlockHeader =
        genesis_block_header.try_into().context("Failed to convert block header")?;

    let genesis_commitment = genesis_header.commitment();
    let genesis = genesis_commitment.to_hex();

    let tls_stage = Builder::new(rpc_url.clone());
    let timeout_stage = if use_tls {
        tls_stage.with_tls().context("Failed to configure TLS for RPC client")?
    } else {
        tls_stage.without_tls()
    };
    let rpc_client = timeout_stage
        .with_timeout(timeout)
        .without_metadata_version()
        .with_metadata_genesis(genesis)
        .without_otel_context_injection()
        .connect()
        .await
        .context("Failed to connect to RPC server with genesis metadata")?;

    Ok(rpc_client)
}

fn get_genesis_header_request() -> BlockHeaderByNumberRequest {
    BlockHeaderByNumberRequest {
        block_num: Some(BlockNumber::GENESIS.as_u32()),
        include_mmr_proof: None,
    }
}

/// Creates a new faucet account and returns it alongside its secret key.
fn create_faucet() -> (Account, SecretKey) {
    let coin_seed: [u64; 4] = rand::rng().random();
    let mut rng = RandomCoin::new(coin_seed.map(Felt::new).into());
    let key_pair = SecretKey::with_rng(&mut rng);
    let init_seed = [0_u8; 32];

    let token_symbol = TokenSymbol::new("TEST").unwrap();
    let token_metadata = FungibleTokenMetadata::builder(
        TokenName::new("TEST").unwrap(),
        token_symbol,
        2,
        FungibleAsset::MAX_AMOUNT,
    )
    .build()
    .unwrap();
    let faucet = AccountBuilder::new(init_seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Private)
        .with_component(token_metadata)
        .with_component(BasicFungibleFaucet)
        .with_components(TokenPolicyManager::new(
            PolicyAuthority::AuthControlled,
            MintPolicyConfig::AllowAll,
            BurnPolicyConfig::AllowAll,
        ))
        .with_auth_component(AuthSingleSig::new(
            key_pair.public_key().into(),
            AuthScheme::Falcon512Poseidon2,
        ))
        .build()
        .unwrap();
    (faucet, key_pair)
}

/// Creates a new wallet account with the given public key, using `index` to vary
/// the init seed so each wallet ends up with a distinct account ID.
fn create_wallet(
    public_key: miden_protocol::crypto::dsa::falcon512_poseidon2::PublicKey,
    index: u64,
) -> Account {
    let init_seed: Vec<_> = index.to_be_bytes().into_iter().chain([0u8; 24]).collect();
    AccountBuilder::new(init_seed.try_into().unwrap())
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Private)
        .with_auth_component(AuthSingleSig::new(public_key.into(), AuthScheme::Falcon512Poseidon2))
        .with_component(BasicWallet)
        .build()
        .unwrap()
}

// BENCHMARK DATA STORE
// ================================================================================================

/// In-memory `DataStore` impl used to feed the [`TransactionExecutor`] when
/// generating real proofs locally. Modelled on the network-monitor's
/// `MonitorDataStore`.
pub struct BenchmarkDataStore {
    accounts: HashMap<AccountId, Account>,
    block_header: BlockHeader,
    partial_block_chain: PartialBlockchain,
    mast_store: TransactionMastStore,
}

impl BenchmarkDataStore {
    pub fn new(block_header: BlockHeader, partial_block_chain: PartialBlockchain) -> Self {
        Self {
            accounts: HashMap::new(),
            block_header,
            partial_block_chain,
            mast_store: TransactionMastStore::new(),
        }
    }

    pub fn add_account(&mut self, account: Account) {
        self.mast_store.load_account_code(account.code());
        self.accounts.insert(account.id(), account);
    }

    pub fn update_account(&mut self, account: Account) {
        self.add_account(account);
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
