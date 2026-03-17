//! Benchmarks for `State::load` performance at different account scales.
//!
//! Measures the time taken by `State::load` with 1e4, 1e5, and 1e6 **public** accounts in the
//! database. Each account carries vault assets and storage data (both plain values and a storage
//! map), so every phase of loading is exercised:
//!
//! - `load_mmr`: rebuilds the chain MMR from block header commitments
//! - `load_account_tree`: rebuilds the account SMT from the DB
//! - `load_nullifier_tree`: rebuilds the nullifier SMT (empty here)
//! - `verify_tree_consistency`: checks tree roots against the block header
//! - `load_smt_forest`: loads per-account SMT forest for vault witnesses and storage-map proofs —
//!   exercised because all accounts are public
//!
//! Span names and elapsed times are printed in **bold yellow** when the bench is run with
//! `--nocapture`. Set `RUST_LOG` to control verbosity (defaults to `miden-store=info`).
//!
//! ```sh
//! RUST_LOG=miden-store=info \
//!   cargo bench --bench state_load -p miden-node-store -- --nocapture
//! ```

use std::fmt;
use std::path::PathBuf;

use criterion::{Criterion, criterion_group, criterion_main};
use miden_crypto::utils::Serializable;
use miden_node_store::Store;
use miden_node_store::genesis::GenesisBlock;
use miden_node_store::state::State;
use miden_node_utils::clap::StorageOptions;
use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountComponentCode,
    AccountComponentMetadata,
    AccountDelta,
    AccountStorageMode,
    AccountType,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::block::account_tree::{AccountTree, account_id_to_smt_key};
use miden_protocol::block::{
    BlockAccountUpdate,
    BlockBody,
    BlockHeader,
    BlockNoteTree,
    BlockNumber,
    BlockProof,
    ProvenBlock,
};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;
use miden_protocol::crypto::merkle::mmr::{Forest, MmrPeaks};
use miden_protocol::crypto::merkle::smt::{LargeSmt, MemoryStorage, Smt};
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
use miden_protocol::transaction::{OrderedTransactionHeaders, TransactionKernel};
use miden_protocol::{EMPTY_WORD, Felt, FieldElement, Word};
use miden_standards::account::auth::AuthSingleSig;
use miden_standards::account::wallets::BasicWallet;
use tempfile::TempDir;
use tracing::Subscriber;
use tracing_subscriber::fmt::format::{FmtSpan, FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::{FmtContext, FormattedFields};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

// CONSTANTS
// ================================================================================================

/// Account counts to benchmark: 1e4, 1e5, 1e6.
const ACCOUNT_COUNTS: &[usize] = &[1_000_000, 100_000];

/// ANSI escape: bold yellow.
const BOLD_YELLOW: &str = "\x1b[1;33m";
/// ANSI escape: reset all attributes.
const RESET: &str = "\x1b[0m";

// TRACING SETUP
// ================================================================================================

/// A `FormatEvent` that renders span names in **bold yellow** and delegates everything else to
/// the standard compact format.
struct BoldYellowSpanFormatter;

impl<S, N> FormatEvent<S, N> for BoldYellowSpanFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> fmt::Result {
        let ansi = writer.has_ansi_escapes();
        let meta = event.metadata();

        // Level
        write!(writer, "{} ", meta.level())?;

        // Span scope: name in bold yellow, stored fields in normal weight.
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                let name = span.metadata().name();
                if ansi {
                    write!(writer, "{BOLD_YELLOW}{name}{RESET}")?;
                } else {
                    write!(writer, "{name}")?;
                }
                let ext = span.extensions();
                if let Some(fields) = ext.get::<FormattedFields<N>>() {
                    if !fields.is_empty() {
                        write!(writer, "{{{}}}", fields.fields)?;
                    }
                }
                write!(writer, ": ")?;
            }
        }

        // Target
        write!(writer, "{}: ", meta.target())?;

        // Event fields (timing fields are coloured by BoldYellowFields below).
        ctx.format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

/// A `FormatFields` that renders `time.busy` and `time.idle` in **bold yellow**; all other
/// fields are rendered normally.
struct BoldYellowFields;

impl<'writer> FormatFields<'writer> for BoldYellowFields {
    fn format_fields<R: tracing_subscriber::field::RecordFields>(
        &self,
        mut writer: Writer<'writer>,
        fields: R,
    ) -> fmt::Result {
        use tracing::field::{Field, Visit};

        let ansi = writer.has_ansi_escapes();

        struct Visitor<'w> {
            writer: Writer<'w>,
            ansi: bool,
            first: bool,
        }

        impl Visit for Visitor<'_> {
            fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
                let sep = if self.first { "" } else { ", " };
                self.first = false;
                let name = field.name();
                let is_timing = name == "time.busy" || name == "time.idle";
                if self.ansi && is_timing {
                    let _ = write!(
                        self.writer,
                        "{sep}{BOLD_YELLOW}{name}{RESET}={BOLD_YELLOW}{value:?}{RESET}",
                    );
                } else {
                    let _ = write!(self.writer, "{sep}{name}={value:?}");
                }
            }
        }

        fields.record(&mut Visitor {
            writer: writer.by_ref(),
            ansi,
            first: true,
        });
        Ok(())
    }
}

/// Installs the global tracing subscriber once. Subsequent calls are silently ignored.
fn init_tracing() {
    let filter = std::env::var("RUST_LOG")
        .map(EnvFilter::new)
        .unwrap_or_else(|_| EnvFilter::new("miden-store=info"));

    let layer = tracing_subscriber::fmt::layer()
        .with_span_events(FmtSpan::CLOSE)
        .with_ansi(true)
        .event_format(BoldYellowSpanFormatter)
        .fmt_fields(BoldYellowFields)
        .with_filter(filter);

    let _ = tracing_subscriber::registry().with(layer).try_init();
}

// ACCOUNT CONSTRUCTION
// ================================================================================================

/// Component name shared across all benchmark accounts.
const DATA_COMPONENT_NAME: &str = "bench::wallet::data";

fn value_slot_name() -> StorageSlotName {
    StorageSlotName::new("bench::wallet::data::balance").expect("valid slot name")
}

fn map_slot_name() -> StorageSlotName {
    StorageSlotName::new("bench::wallet::data::ledger").expect("valid slot name")
}

/// Builds one public account with:
/// - a `BasicWallet` component (pre-compiled, `LazyLock`-cached)
/// - a data component with one value slot and one two-entry storage map
/// - an `AuthSingleSig` auth component (pre-compiled, `LazyLock`-cached)
/// - one fungible vault asset
///
/// `wallet_code` is the pre-compiled `BasicWallet` library reused across all accounts so that
/// MASM compilation only happens once (it is backed by a `LazyLock` inside `miden-standards`).
/// All numeric data is derived from the seed so every account holds distinct state.
fn build_public_account(
    seed: [u8; 32],
    faucet_id: miden_protocol::account::AccountId,
    wallet_code: AccountComponentCode,
) -> Account {
    let balance_value = Word::from([
        Felt::new(seed[0] as u64 + 1),
        Felt::new(seed[1] as u64 + 1),
        Felt::new(seed[2] as u64 + 1),
        Felt::new(seed[3] as u64 + 1),
    ]);

    let storage_map = StorageMap::with_entries([
        (
            StorageMapKey::from_index(seed[4] as u32 + 1),
            Word::from([Felt::new(seed[5] as u64 + 1), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        ),
        (
            StorageMapKey::from_index(seed[6] as u32 + 128),
            Word::from([Felt::new(seed[7] as u64 + 1), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        ),
    ])
    .expect("valid storage map entries");

    // Reuse the pre-compiled wallet code (cloned cheaply — it's an Arc-backed Library).
    let data_component = AccountComponent::new(
        wallet_code.clone(),
        vec![
            StorageSlot::with_value(value_slot_name(), balance_value),
            StorageSlot::with_map(map_slot_name(), storage_map),
        ],
        AccountComponentMetadata::new(DATA_COMPONENT_NAME).with_supports_all_types(),
    )
    .expect("data component should be valid");

    let asset_amount = (seed[8] as u64 + 1) * 100;
    let fungible_asset = FungibleAsset::new(faucet_id, asset_amount).expect("valid fungible asset");

    AccountBuilder::new(seed)
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_component(BasicWallet)
        .with_component(data_component)
        .with_assets([Asset::Fungible(fungible_asset)])
        .with_auth_component(AuthSingleSig::new(
            PublicKeyCommitment::from(EMPTY_WORD),
            AuthScheme::Falcon512Rpo,
        ))
        .build_existing()
        .expect("account should build successfully")
}

// BENCHMARK SETUP
// ================================================================================================

/// Creates a fully bootstrapped data directory with `num_accounts` public accounts.
///
/// Every account carries a vault asset and storage data so that `load_smt_forest` has real work
/// to do. The returned [`TempDir`] must be kept alive for the duration of the benchmark.
fn setup_data_directory(num_accounts: usize) -> (TempDir, PathBuf) {
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let data_dir = temp_dir.path().to_path_buf();

    let faucet_id = miden_protocol::account::AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
        .expect("valid faucet account id");

    // Precompile the BasicWallet library once; `AccountComponentCode` is `Clone` (Arc-backed).
    let wallet_code: AccountComponentCode = AccountComponent::from(BasicWallet).into();

    tracing::info!(num_accounts=%num_accounts, "Building accounts....");
    let accounts = Vec::<Account>::from_iter((0..num_accounts).map(|i| {
        let src = Felt::new(i as u64 + 235230).to_bytes();
        let mut seed = [0u8; 32];
        seed[0..src.len()].copy_from_slice(&src[..]);
        build_public_account(seed, faucet_id, wallet_code.clone())
    }));
    tracing::info!(num_accounts=%num_accounts, "Building accounts >> DONE");

    tracing::info!(num_accounts=%num_accounts, "Building genesis block....");
    let genesis_block = build_genesis_block(accounts);
    tracing::info!(num_accounts=%num_accounts, "Building genesis block >> DONE");

    tracing::info!(num_accounts=%num_accounts, "Bootstraping....");
    Store::bootstrap(&genesis_block, &data_dir).expect("Store::bootstrap failed");
    tracing::info!(num_accounts=%num_accounts, "Bootstraping >> DONE");

    (temp_dir, data_dir)
}

/// Wraps the account list in a `GenesisBlock` with consistent account-tree and nullifier-tree
/// roots so that `verify_tree_consistency` passes on every `State::load` call.
fn build_genesis_block(accounts: Vec<Account>) -> GenesisBlock {
    let account_updates: Vec<BlockAccountUpdate> = accounts
        .iter()
        .map(|account| {
            let delta = AccountDelta::try_from(account.clone())
                .expect("full-state delta should always succeed");
            BlockAccountUpdate::new(
                account.id(),
                account.to_commitment(),
                AccountUpdateDetails::Delta(delta),
            )
        })
        .collect();

    let smt_entries = accounts.iter().map(|a| (account_id_to_smt_key(a.id()), a.to_commitment()));
    let smt = LargeSmt::with_entries(MemoryStorage::default(), smt_entries)
        .expect("failed to build account SMT");
    let account_tree = AccountTree::new(smt).expect("failed to create AccountTree");

    let secret_key = SecretKey::new();
    let header = BlockHeader::new(
        1_u32,
        Word::empty(),
        BlockNumber::GENESIS,
        MmrPeaks::new(Forest::empty(), Vec::new())
            .expect("empty MmrPeaks is always valid")
            .hash_peaks(),
        account_tree.root(),
        Smt::new().root(),
        BlockNoteTree::empty().root(),
        Word::empty(),
        TransactionKernel.to_commitment(),
        secret_key.public_key(),
        miden_node_utils::fee::test_fee_params(),
        0_u32,
    );
    let signature = secret_key.sign(header.commitment());

    let body = BlockBody::new_unchecked(
        account_updates,
        vec![],
        vec![],
        OrderedTransactionHeaders::new_unchecked(vec![]),
    );

    let proven = ProvenBlock::new_unchecked(header, body, signature, BlockProof::new_dummy());
    GenesisBlock::try_from(proven).expect("synthetic genesis block should be valid")
}

// BENCHMARK FUNCTIONS
// ================================================================================================

fn bench_state_load(c: &mut Criterion) {
    init_tracing();

    let mut group = c.benchmark_group("state_load");

    for &num_accounts in ACCOUNT_COUNTS {
        let (_temp_dir, data_dir) = setup_data_directory(num_accounts);

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build Tokio runtime");

        group.bench_function(format!("{num_accounts}_accounts"), |b| {
            b.iter(|| {
                let data_dir = data_dir.clone();
                rt.block_on(async move {
                    let (termination_ask, _rx) = tokio::sync::mpsc::channel(1);
                    let state = State::load(&data_dir, StorageOptions::default(), termination_ask)
                        .await
                        .expect("State::load failed during benchmark");
                    // Drop inside the async context so the Db pool shuts down while
                    // a Tokio runtime is still active.
                    drop(state);
                })
            });
        });
    }

    group.finish();
}

criterion_group!(
    name = state_load;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(600))
        .warm_up_time(std::time::Duration::from_secs(3));
    targets = bench_state_load
);
criterion_main!(state_load);
