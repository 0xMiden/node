use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use futures::{StreamExt, stream};
use miden_node_proto::generated::store::rpc_client::RpcClient;
use miden_node_proto::generated::{self as proto};
use miden_node_store::state::State;
use miden_node_utils::clap::StorageOptions;
use miden_node_utils::tracing::grpc::OtelInterceptor;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::note::{NoteDetails, NoteTag};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use rand::Rng;
use rand::seq::SliceRandom;
use tokio::fs;
use tokio::time::sleep;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;

use crate::seeding::{ACCOUNTS_FILENAME, start_store};
use crate::store::metrics::print_summary;

mod metrics;

// CONSTANTS
// ================================================================================================

/// Number of accounts used in each `sync_notes` call.
const ACCOUNTS_PER_SYNC_NOTES: usize = 15;

/// Number of note IDs used in each `sync_nullifiers` call.
const NOTE_IDS_PER_NULLIFIERS_CHECK: usize = 20;

/// Number of attempts the benchmark will make to reach the store before proceeding.
const STORE_STATUS_RETRIES: usize = 10;

// GET ACCOUNT
// ================================================================================================

/// Sends multiple `get_account` requests to the store and prints the performance.
///
/// Each request asks for all entries in `storage_map_slot`, which is intended to exercise the
/// storage-map reconstruction path for public accounts seeded by this stress-test tool.
pub async fn bench_get_account(
    data_directory: PathBuf,
    iterations: usize,
    concurrency: usize,
    storage_map_slot: String,
) {
    let accounts_file = data_directory.join(ACCOUNTS_FILENAME);
    let accounts = fs::read_to_string(&accounts_file)
        .await
        .unwrap_or_else(|e| panic!("missing file {}: {e:?}", accounts_file.display()));
    let mut account_ids: Vec<AccountId> = accounts
        .lines()
        .map(|a| AccountId::from_hex(a).expect("invalid account id"))
        .filter(AccountId::has_public_state)
        .collect();

    assert!(
        !account_ids.is_empty(),
        "no public accounts found in {}; seed with --public-accounts-percentage > 0",
        accounts_file.display()
    );

    let mut rng = rand::rng();
    account_ids.shuffle(&mut rng);
    let mut account_ids = account_ids.into_iter().cycle();

    let (store_client, _) = start_store(data_directory).await;

    wait_for_store(&store_client).await.unwrap();

    let request = |_| {
        let mut client = store_client.clone();
        let account_id = account_ids.next().expect("cycled public account ids never end");
        let storage_map_slot = storage_map_slot.clone();
        tokio::spawn(async move { get_account(&mut client, account_id, storage_map_slot).await })
    };

    let results = stream::iter(0..iterations)
        .map(request)
        .buffer_unordered(concurrency)
        .map(|res| res.unwrap())
        .collect::<Vec<_>>()
        .await;

    let timers_accumulator: Vec<Duration> = results.iter().map(|r| r.duration).collect();
    print_summary(&timers_accumulator);

    let total_runs = results.len();
    let storage_map_limit_exceeded =
        results.iter().filter(|r| r.storage_map_limit_exceeded).count();
    let vault_limit_exceeded = results.iter().filter(|r| r.vault_limit_exceeded).count();
    #[expect(clippy::cast_precision_loss)]
    let average_storage_map_entries = if total_runs > 0 {
        results.iter().map(|r| r.storage_map_entries as f64).sum::<f64>() / total_runs as f64
    } else {
        0.0
    };
    #[expect(clippy::cast_precision_loss)]
    let average_vault_assets = if total_runs > 0 {
        results.iter().map(|r| r.vault_assets as f64).sum::<f64>() / total_runs as f64
    } else {
        0.0
    };

    println!("GetAccount statistics:");
    println!("  Total runs: {total_runs}");
    println!("  Storage map limit exceeded responses: {storage_map_limit_exceeded}");
    println!("  Average returned storage map entries: {average_storage_map_entries:.2}");
    println!("  Vault limit exceeded responses: {vault_limit_exceeded}");
    println!("  Average returned vault assets: {average_vault_assets:.2}");
}

#[derive(Clone)]
struct GetAccountRun {
    duration: Duration,
    storage_map_entries: usize,
    storage_map_limit_exceeded: bool,
    vault_assets: usize,
    vault_limit_exceeded: bool,
}

async fn get_account(
    api_client: &mut RpcClient<InterceptedService<Channel, OtelInterceptor>>,
    account_id: AccountId,
    storage_map_slot: String,
) -> GetAccountRun {
    use proto::rpc::account_storage_details::account_storage_map_details::Entries;

    let request = get_account_request(account_id, storage_map_slot);

    let start = Instant::now();
    let response = api_client.get_account(request).await.unwrap().into_inner();
    let duration = start.elapsed();

    let details = response.details;
    let map_details = details
        .as_ref()
        .and_then(|details| details.storage_details.as_ref())
        .and_then(|storage_details| storage_details.map_details.first());
    let (storage_map_entries, storage_map_limit_exceeded) = match map_details {
        Some(details) if details.too_many_entries => (0, true),
        Some(details) => match &details.entries {
            Some(Entries::AllEntries(entries)) => (entries.entries.len(), false),
            _ => (0, false),
        },
        None => (0, false),
    };

    let vault_details = details.and_then(|details| details.vault_details);
    let (vault_assets, vault_limit_exceeded) = match vault_details {
        Some(details) if details.too_many_assets => (0, true),
        Some(details) => (details.assets.len(), false),
        None => (0, false),
    };

    GetAccountRun {
        duration,
        storage_map_entries,
        storage_map_limit_exceeded,
        vault_assets,
        vault_limit_exceeded,
    }
}

fn get_account_request(
    account_id: AccountId,
    storage_map_slot: String,
) -> proto::rpc::AccountRequest {
    use proto::rpc::account_request::AccountDetailRequest;
    use proto::rpc::account_request::account_detail_request::StorageMapDetailRequest;
    use proto::rpc::account_request::account_detail_request::storage_map_detail_request::SlotData;

    proto::rpc::AccountRequest {
        account_id: Some(proto::account::AccountId { id: account_id.to_bytes() }),
        block_num: None,
        details: Some(AccountDetailRequest {
            code_commitment: None,
            asset_vault_commitment: Some(proto::primitives::Digest::from(Word::empty())),
            storage_maps: vec![StorageMapDetailRequest {
                slot_name: storage_map_slot,
                slot_data: Some(SlotData::AllEntries(true)),
            }],
        }),
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;

    use super::*;

    #[test]
    fn get_account_request_includes_vault_details() {
        let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE)
            .expect("test account id should be valid");
        let request = get_account_request(
            account_id,
            crate::seeding::BENCHMARK_STORAGE_MAP_SLOT_NAME.to_string(),
        );

        let details = request.details.expect("details should be requested");
        assert!(
            details.asset_vault_commitment.is_some(),
            "benchmark get-account should request vault asset details"
        );
    }
}

// SYNC NOTES
// ================================================================================================

/// Sends multiple `sync_notes` requests to the store and prints the performance.
///
/// Arguments:
/// - `data_directory`: directory that contains the database dump file and the accounts ids dump
///   file.
/// - `iterations`: number of requests to send.
/// - `concurrency`: number of requests to send in parallel.
pub async fn bench_sync_notes(data_directory: PathBuf, iterations: usize, concurrency: usize) {
    // load accounts from the dump file
    let accounts_file = data_directory.join(ACCOUNTS_FILENAME);
    let accounts = fs::read_to_string(&accounts_file)
        .await
        .unwrap_or_else(|e| panic!("missing file {}: {e:?}", accounts_file.display()));
    let mut account_ids = accounts.lines().map(|a| AccountId::from_hex(a).unwrap()).cycle();

    let (store_client, _) = start_store(data_directory).await;

    wait_for_store(&store_client).await.unwrap();

    // Get the latest block number to determine the range
    let status = store_client.clone().status(()).await.unwrap().into_inner();
    let chain_tip = status.chain_tip;

    // each request will have `ACCOUNTS_PER_SYNC_NOTES` note tags and will be sent with block number
    // 0.
    let request = |_| {
        let mut client = store_client.clone();
        let account_batch: Vec<AccountId> =
            account_ids.by_ref().take(ACCOUNTS_PER_SYNC_NOTES).collect();
        tokio::spawn(async move { sync_notes(&mut client, account_batch, chain_tip).await })
    };

    // create a stream of tasks to send the requests
    let timers_accumulator = stream::iter(0..iterations)
        .map(request)
        .buffer_unordered(concurrency)
        .map(|res| res.unwrap())
        .collect::<Vec<_>>()
        .await;

    print_summary(&timers_accumulator);
}

/// Sends a single `sync_notes` request to the store and returns the elapsed time. The note tags are
/// generated from the account ids, so the request will contain a note tag for each account id, with
/// a block number of 0.
pub async fn sync_notes(
    api_client: &mut RpcClient<InterceptedService<Channel, OtelInterceptor>>,
    account_ids: Vec<AccountId>,
    chain_tip: u32,
) -> Duration {
    let note_tags = account_ids
        .iter()
        .map(|id| u32::from(NoteTag::with_account_target(*id)))
        .collect::<Vec<_>>();
    let sync_request = proto::rpc::SyncNotesRequest {
        block_range: Some(proto::rpc::BlockRange { block_from: 0, block_to: chain_tip }),
        note_tags,
    };

    let start = Instant::now();
    api_client.sync_notes(sync_request).await.unwrap();
    start.elapsed()
}

// SYNC NULLIFIERS
// ================================================================================================

/// Sends multiple `sync_nullifiers` requests to the store and prints the performance.
///
/// Arguments:
/// - `data_directory`: directory that contains the database dump file and the accounts ids dump
///   file.
/// - `iterations`: number of requests to send.
/// - `concurrency`: number of requests to send in parallel.
/// - `prefixes_per_request`: number of prefixes to send in each request.
pub async fn bench_sync_nullifiers(
    data_directory: PathBuf,
    iterations: usize,
    concurrency: usize,
    prefixes_per_request: usize,
) {
    let (mut store_client, _) = start_store(data_directory.clone()).await;

    wait_for_store(&store_client).await.unwrap();

    let accounts_file = data_directory.join(ACCOUNTS_FILENAME);
    let accounts = fs::read_to_string(&accounts_file)
        .await
        .unwrap_or_else(|e| panic!("missing file {}: {e:?}", accounts_file.display()));
    let account_ids: Vec<AccountId> = accounts
        .lines()
        .take(ACCOUNTS_PER_SYNC_NOTES)
        .map(|a| AccountId::from_hex(a).unwrap())
        .collect();

    // Get the latest block number to determine the range
    let status = store_client.clone().status(()).await.unwrap().into_inner();
    let chain_tip = status.chain_tip;

    // Get all nullifier prefixes from the store using sync_notes
    let mut nullifier_prefixes: Vec<u32> = vec![];
    let mut current_block_num = 0;
    loop {
        // Get the accounts notes using sync_notes
        let note_tags: Vec<u32> = account_ids
            .iter()
            .map(|id| u32::from(NoteTag::with_account_target(*id)))
            .collect();
        let sync_request = proto::rpc::SyncNotesRequest {
            block_range: Some(proto::rpc::BlockRange {
                block_from: current_block_num,
                block_to: chain_tip,
            }),
            note_tags,
        };
        let response = store_client.sync_notes(sync_request).await.unwrap().into_inner();

        let pagination = response.pagination_info.expect("pagination_info should exist");
        let last_block_checked = pagination.block_num;

        if response.blocks.is_empty() || last_block_checked >= pagination.chain_tip {
            break;
        }

        // Collect note IDs from all blocks in the response.
        let note_ids: Vec<_> = response
            .blocks
            .iter()
            .flat_map(|b| {
                b.notes.iter().map(|n| n.inclusion_proof.as_ref().unwrap().note_id.unwrap())
            })
            .collect();

        // Get the notes nullifiers, limiting to 20 notes maximum.
        let note_ids_to_fetch: Vec<_> =
            note_ids.iter().take(NOTE_IDS_PER_NULLIFIERS_CHECK).copied().collect();
        if !note_ids_to_fetch.is_empty() {
            let notes = store_client
                .get_notes_by_id(proto::note::NoteIdList { ids: note_ids_to_fetch })
                .await
                .unwrap()
                .into_inner()
                .notes;

            nullifier_prefixes.extend(notes.iter().filter_map(|n| {
                let details_bytes = n.note.as_ref()?.details.as_ref()?;
                let details = NoteDetails::read_from_bytes(details_bytes).unwrap();
                Some(u32::from(details.nullifier().prefix()))
            }));
        }

        // Resume from the next block after the last one checked.
        current_block_num = last_block_checked + 1;
    }
    let mut nullifiers = nullifier_prefixes.into_iter().cycle();

    // Each request will have `prefixes_per_request` prefixes and block number 0
    let request = |_| {
        let mut client = store_client.clone();

        let nullifiers_batch: Vec<u32> = nullifiers.by_ref().take(prefixes_per_request).collect();

        tokio::spawn(async move { sync_nullifiers(&mut client, nullifiers_batch, chain_tip).await })
    };

    // Create a stream of tasks to send the requests
    let (timers_accumulator, responses) = stream::iter(0..iterations)
        .map(request)
        .buffer_unordered(concurrency)
        .map(|res| res.unwrap())
        .collect::<(Vec<_>, Vec<_>)>()
        .await;

    print_summary(&timers_accumulator);

    #[expect(clippy::cast_precision_loss)]
    let average_nullifiers_per_response =
        responses.iter().map(|r| r.nullifiers.len()).sum::<usize>() as f64 / responses.len() as f64;
    println!("Average nullifiers per response: {average_nullifiers_per_response}");
}

/// Sends a single `sync_nullifiers` request to the store and returns:
/// - the elapsed time.
/// - the response.
async fn sync_nullifiers(
    api_client: &mut RpcClient<InterceptedService<Channel, OtelInterceptor>>,
    nullifiers_prefixes: Vec<u32>,
    chain_tip: u32,
) -> (Duration, proto::rpc::SyncNullifiersResponse) {
    let sync_request = proto::rpc::SyncNullifiersRequest {
        block_range: Some(proto::rpc::BlockRange { block_from: 0, block_to: chain_tip }),
        nullifiers: nullifiers_prefixes,
        prefix_len: 16,
    };

    let start = Instant::now();
    let response = api_client.sync_nullifiers(sync_request).await.unwrap();
    (start.elapsed(), response.into_inner())
}

// SYNC TRANSACTIONS
// ================================================================================================

/// Sends multiple `sync_transactions` requests to the store and prints the performance.
///
/// Arguments:
/// - `data_directory`: directory that contains the database dump file and the accounts ids dump
///   file.
/// - `iterations`: number of requests to send.
/// - `concurrency`: number of requests to send in parallel.
/// - `accounts_per_request`: number of accounts to sync transactions for in each request.
pub async fn bench_sync_transactions(
    data_directory: PathBuf,
    iterations: usize,
    concurrency: usize,
    accounts_per_request: usize,
    block_range_size: u32,
) {
    // load accounts from the dump file
    let accounts_file = data_directory.join(ACCOUNTS_FILENAME);
    let accounts = fs::read_to_string(&accounts_file)
        .await
        .unwrap_or_else(|e| panic!("missing file {}: {e:?}", accounts_file.display()));
    let mut account_ids: Vec<AccountId> = accounts
        .lines()
        .map(|a| AccountId::from_hex(a).expect("invalid account id"))
        .collect();
    // Shuffle once so the cycling iterator starts in a random order.
    let mut rng = rand::rng();
    account_ids.shuffle(&mut rng);
    let mut account_ids = account_ids.into_iter().cycle();

    let (store_client, _) = start_store(data_directory).await;

    wait_for_store(&store_client).await.unwrap();

    // Get the latest block number to determine the range
    let status = store_client.clone().status(()).await.unwrap().into_inner();
    let chain_tip = status.chain_tip;

    // each request will have `accounts_per_request` account ids and will query a range of blocks
    let request = |_| {
        let mut client = store_client.clone();
        let account_batch: Vec<AccountId> =
            account_ids.by_ref().take(accounts_per_request).collect();

        // Pick a random window of size `block_range_size` that fits before `chain_tip`.
        let max_start = chain_tip.saturating_sub(block_range_size);
        let start_block = rand::rng().random_range(0..=max_start);
        let end_block = start_block.saturating_add(block_range_size).min(chain_tip);

        tokio::spawn(async move {
            sync_transactions_paginated(&mut client, account_batch, start_block, end_block).await
        })
    };

    // create a stream of tasks to send sync_transactions requests
    let results = stream::iter(0..iterations)
        .map(request)
        .buffer_unordered(concurrency)
        .map(|res| res.unwrap())
        .collect::<Vec<_>>()
        .await;

    let timers_accumulator: Vec<Duration> = results.iter().map(|r| r.duration).collect();
    let responses: Vec<proto::rpc::SyncTransactionsResponse> =
        results.iter().map(|r| r.response.clone()).collect();

    print_summary(&timers_accumulator);

    #[expect(clippy::cast_precision_loss)]
    let average_transactions_per_response = if responses.is_empty() {
        0.0
    } else {
        responses.iter().map(|r| r.transactions.len()).sum::<usize>() as f64
            / responses.len() as f64
    };
    println!("Average transactions per response: {average_transactions_per_response}");

    // Calculate pagination statistics
    let total_runs = results.len();
    let paginated_runs = results.iter().filter(|r| r.pages > 1).count();
    #[expect(clippy::cast_precision_loss)]
    let pagination_rate = if total_runs > 0 {
        (paginated_runs as f64 / total_runs as f64) * 100.0
    } else {
        0.0
    };
    #[expect(clippy::cast_precision_loss)]
    let avg_pages = if total_runs > 0 {
        results.iter().map(|r| r.pages as f64).sum::<f64>() / total_runs as f64
    } else {
        0.0
    };

    println!("Pagination statistics:");
    println!("  Total runs: {total_runs}");
    println!("  Runs triggering pagination: {paginated_runs}");
    println!("  Pagination rate: {pagination_rate:.2}%");
    println!("  Average pages per run: {avg_pages:.2}");
}

/// Sends a single `sync_transactions` request to the store and returns a tuple with:
/// - the elapsed time.
/// - the response.
pub async fn sync_transactions(
    api_client: &mut RpcClient<InterceptedService<Channel, OtelInterceptor>>,
    account_ids: Vec<AccountId>,
    block_from: u32,
    block_to: u32,
) -> (Duration, proto::rpc::SyncTransactionsResponse) {
    let account_ids = account_ids
        .iter()
        .map(|id| proto::account::AccountId { id: id.to_bytes() })
        .collect::<Vec<_>>();

    let sync_request = proto::rpc::SyncTransactionsRequest {
        block_range: Some(proto::rpc::BlockRange { block_from, block_to }),
        account_ids,
    };

    let start = Instant::now();
    let response = api_client.sync_transactions(sync_request).await.unwrap();
    (start.elapsed(), response.into_inner())
}

#[derive(Clone)]
struct SyncTransactionsRun {
    duration: Duration,
    response: proto::rpc::SyncTransactionsResponse,
    pages: usize,
}

async fn sync_transactions_paginated(
    api_client: &mut RpcClient<InterceptedService<Channel, OtelInterceptor>>,
    account_ids: Vec<AccountId>,
    block_from: u32,
    block_to: u32,
) -> SyncTransactionsRun {
    let mut total_duration = Duration::default();
    let mut aggregated_records = Vec::new();
    let mut next_block_from = block_from;
    let mut target_block_to = block_to;
    let mut pages = 0usize;
    let mut final_pagination_info = None;

    loop {
        if next_block_from > target_block_to {
            break;
        }

        let (elapsed, response) =
            sync_transactions(api_client, account_ids.clone(), next_block_from, target_block_to)
                .await;
        total_duration += elapsed;
        pages += 1;

        let info = response.pagination_info.unwrap_or(proto::rpc::PaginationInfo {
            chain_tip: target_block_to,
            block_num: target_block_to,
        });

        aggregated_records.extend(response.transactions.into_iter());
        let reached_block = info.block_num;
        let chain_tip = info.chain_tip;
        final_pagination_info =
            Some(proto::rpc::PaginationInfo { chain_tip, block_num: reached_block });

        if reached_block >= chain_tip {
            break;
        }

        // Resume from the next block after the last one fully included.
        next_block_from = reached_block + 1;
        target_block_to = chain_tip;
    }

    SyncTransactionsRun {
        duration: total_duration,
        response: proto::rpc::SyncTransactionsResponse {
            pagination_info: final_pagination_info,
            transactions: aggregated_records,
        },
        pages,
    }
}

// SYNC CHAIN MMR
// ================================================================================================

/// Sends multiple `sync_chain_mmr` requests to the store and prints the performance.
///
/// Arguments:
/// - `data_directory`: directory that contains the database dump file.
/// - `iterations`: number of requests to send.
/// - `concurrency`: number of requests to send in parallel.
pub async fn bench_sync_chain_mmr(data_directory: PathBuf, iterations: usize, concurrency: usize) {
    let (store_client, _) = start_store(data_directory).await;

    wait_for_store(&store_client).await.unwrap();

    let chain_tip = store_client.clone().status(()).await.unwrap().into_inner().chain_tip;

    let request = |_| {
        let mut client = store_client.clone();
        tokio::spawn(async move { sync_chain_mmr(&mut client, chain_tip).await })
    };

    let results = stream::iter(0..iterations)
        .map(request)
        .buffer_unordered(concurrency)
        .map(|res| res.unwrap())
        .collect::<Vec<_>>()
        .await;

    let timers_accumulator: Vec<Duration> = results.iter().map(|r| r.duration).collect();

    print_summary(&timers_accumulator);

    let total_runs = results.len();

    println!("Pagination statistics:");
    println!("  Total runs: {total_runs}");
}

/// Sends a single `sync_chain_mmr` request to the store and returns a tuple with:
/// - the elapsed time.
/// - the response.
async fn sync_chain_mmr(
    api_client: &mut RpcClient<InterceptedService<Channel, OtelInterceptor>>,
    current_client_block_height: u32,
) -> SyncChainMmrRun {
    let sync_request = proto::rpc::SyncChainMmrRequest {
        current_client_block_height,
        finality_level: proto::rpc::FinalityLevel::Committed.into(),
    };

    let start = Instant::now();
    let response = api_client.sync_chain_mmr(sync_request).await.unwrap();
    let elapsed = start.elapsed();
    let response = response.into_inner();
    let _mmr_delta = response.mmr_delta.expect("mmr_delta should exist");
    SyncChainMmrRun { duration: elapsed }
}

#[derive(Clone)]
struct SyncChainMmrRun {
    duration: Duration,
}

// LOAD STATE
// ================================================================================================

pub async fn load_state(data_directory: &Path) {
    let start = Instant::now();
    let (termination_ask, _) = tokio::sync::mpsc::channel(1);
    let _state = State::load(data_directory, StorageOptions::default(), termination_ask)
        .await
        .unwrap();
    let elapsed = start.elapsed();

    // Get database path and run SQL commands to count records
    let data_directory =
        miden_node_store::DataDirectory::load(data_directory.to_path_buf()).unwrap();
    let database_filepath = data_directory.database_path();

    // Use sqlite3 command to count records
    let account_count = std::process::Command::new("sqlite3")
        .arg(database_filepath.to_str().unwrap())
        .arg("SELECT COUNT(*) FROM accounts;")
        .output()
        .map_or_else(
            |_| "unknown".to_string(),
            |output| String::from_utf8_lossy(&output.stdout).trim().to_string(),
        );

    let nullifier_count = std::process::Command::new("sqlite3")
        .arg(database_filepath.to_str().unwrap())
        .arg("SELECT COUNT(*) FROM nullifiers;")
        .output()
        .map_or_else(
            |_| "unknown".to_string(),
            |output| String::from_utf8_lossy(&output.stdout).trim().to_string(),
        );

    println!("State loaded in {elapsed:?}");
    println!("Database contains {account_count} accounts and {nullifier_count} nullifiers");
}

// HELPERS
// ================================================================================================

/// Waits for the store to be ready and accepting requests.
///
/// Periodically checks the store’s status endpoint until it reports `"connected"`.
/// Returns an error if the status does not become `"connected"` after
/// [`STORE_STATUS_RETRIES`] attempts.
async fn wait_for_store(
    store_client: &RpcClient<InterceptedService<Channel, OtelInterceptor>>,
) -> Result<(), String> {
    for _ in 0..STORE_STATUS_RETRIES {
        // Get status from the store component to confirm that it is ready.
        let status = store_client.clone().status(()).await.unwrap().into_inner();

        if status.status == "connected" {
            return Ok(());
        }

        sleep(Duration::from_millis(500)).await;
    }

    Err("Store component failed to start".to_string())
}
