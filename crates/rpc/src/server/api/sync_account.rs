use std::collections::BTreeMap;
use std::num::{NonZeroU32, NonZeroUsize};

use miden_node_proto::domain::account::{AccountSyncState, AccountSyncUpdate, SyncAccountResponse};
use miden_node_proto::domain::block::SyncRange;
use miden_node_proto::{DecodeMessage, Verify, generated as proto};
use miden_node_store::{AccountSize, DatabaseError, ReadTx, ScopedBlockNum, queries};
use miden_node_tracing::{instrument, miden_span_record};
use miden_protocol::Word;
use miden_protocol::account::{AccountHeader, AccountId, AccountStorageHeader};
use tonic::{Code, Status};

use super::error_codes::SyncAccountErrorCode as ErrorCode;
use super::{RpcService, database_error_to_status};

type Input = (AccountId, SyncRange);

#[tonic::async_trait]
impl proto::server::miden_node_v2_node_service::SyncAccount for RpcService {
    type Input = Input;
    type Output = SyncAccountResponse;

    fn decode(request: proto::miden::node::v2::SyncAccountRequest) -> tonic::Result<Input> {
        let request = request
            .decode_fields()
            .map_err(|err| ErrorCode::DeserializationFailed.invalid_argument(err))?;
        let account = request
            .account_id
            .verify()
            .map_err(|err| ErrorCode::DeserializationFailed.invalid_argument(err))?;
        let range = request
            .range
            .verify()
            .map_err(|err| ErrorCode::InvalidRange.invalid_argument(err))?;
        Ok((account, range))
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::miden::node::v2::SyncAccountResponse> {
        output.try_into().map_err(|err| super::error_codes::log_internal_error(&err))
    }

    #[instrument(name = "sync_account", err)]
    async fn handle(
        &self,
        (account, range): Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        miden_span_record!(
            account.id = account,
            block_range.from = range.from_exclusive,
            block_range.to = range.target,
        );

        let config = self.sync_account;
        self.state
            .with_view(async |view| {
                let blocks = range.from_exclusive.unwrap_or(range.target)..=range.target;
                view.read(blocks, move |tx, blocks| {
                    let target = blocks.scoped_end();
                    let from = range.from_exclusive.map(|_| blocks.scoped_start());
                    let size = queries::account_size(tx, account, target)
                        .map_err(database_error_to_sync_status)?;
                    check_account_size(size, config.limit)?;

                    let update = read_account_update(
                        tx,
                        account,
                        from,
                        target,
                        size.storage_map_entries + size.vault_assets,
                        config,
                    )?;

                    Ok(SyncAccountResponse { block_num: range.target, update })
                })
                .await
                .map_err(database_error_to_sync_status)?
            })
            .await
    }
}

fn check_account_size(size: AccountSize, limit: NonZeroU32) -> tonic::Result<()> {
    if size.total() > u64::from(limit.get()) {
        return Err(Status::with_details(
            Code::ResourceExhausted,
            format!("account has {size:?}, exceeding the configured total of {limit} entries"),
            vec![ErrorCode::AccountTooLarge as u8].into(),
        ));
    }
    Ok(())
}

/// Returns an empty delta for unchanged accounts, a snapshot for small accounts, or a capped delta.
/// Missing starting state and overflowing deltas select a snapshot.
fn read_account_update(
    tx: &ReadTx<'_>,
    account: AccountId,
    from: Option<ScopedBlockNum>,
    target: ScopedBlockNum,
    account_entries: u64,
    config: crate::SyncAccountConfig,
) -> tonic::Result<AccountSyncUpdate> {
    // An omitted starting block requests a full account snapshot.
    let Some(from) = from else {
        return read_account_snapshot(tx, account, target);
    };

    // The account may not have existed at the starting block, or its history may be pruned.
    let Some((header, storage_header)) = account_headers_at(tx, account, from)? else {
        return read_account_snapshot(tx, account, target);
    };

    // Matching commitments mean the client already has the target state; skip entry reads.
    let (target_header, _) =
        queries::account_headers(tx, account, target).map_err(database_error_to_sync_status)?;
    if header.to_commitment() == target_header.to_commitment() {
        return Ok(AccountSyncUpdate::Delta(AccountSyncState {
            header,
            storage_header,
            maps: BTreeMap::new(),
            vault: BTreeMap::new(),
        }));
    }

    if account_entries <= u64::from(config.snapshot_threshold) {
        return read_account_snapshot(tx, account, target);
    }

    let delta_limit = NonZeroUsize::new(config.delta_limit.get() as usize)
        .expect("delta limit is nonzero and fits usize");
    if let Some(delta) = read_account_delta(tx, account, from, target, delta_limit)? {
        return Ok(AccountSyncUpdate::Delta(delta));
    }

    read_account_snapshot(tx, account, target)
}

/// Returns the account headers at a block, or `None` if the account was absent or history was
/// pruned.
fn account_headers_at(
    tx: &ReadTx<'_>,
    account: AccountId,
    block: ScopedBlockNum,
) -> tonic::Result<Option<(AccountHeader, AccountStorageHeader)>> {
    match queries::account_headers(tx, account, block) {
        Ok(headers) => Ok(Some(headers)),
        Err(DatabaseError::BlockPruned { .. } | DatabaseError::AccountNotFoundInDb(_)) => Ok(None),
        Err(err) => Err(database_error_to_sync_status(err)),
    }
}

fn read_account_snapshot(
    tx: &ReadTx<'_>,
    account: AccountId,
    target: ScopedBlockNum,
) -> tonic::Result<AccountSyncUpdate> {
    queries::account_state(tx, account, target)
        .map(AccountSyncUpdate::Snapshot)
        .map_err(database_error_to_sync_status)
}

/// Reads a delta with a shared entry cap across storage maps and the vault.
///
/// Fetches one storage-map page, then one vault page using the remaining budget. A continuation
/// cursor selects a snapshot. If storage uses the full budget, a one-item vault page checks for
/// overflow. Page lookahead loads at most two entries beyond the cap in that case.
/// The cap bounds entries loaded, not historical rows scanned by SQLite.
///
/// Counting the delta first would add a separate query over the same history. Maintaining change
/// counters would add bookkeeping and overestimate deltas when keys change repeatedly. Capped
/// reads are simpler and reuse the fetched entries when the delta fits, at the cost of discarding
/// them when a snapshot is needed.
fn read_account_delta(
    tx: &ReadTx<'_>,
    account: AccountId,
    from: ScopedBlockNum,
    target: ScopedBlockNum,
    entry_limit: NonZeroUsize,
) -> tonic::Result<Option<AccountSyncState>> {
    let (header, storage_header) =
        queries::account_headers(tx, account, target).map_err(database_error_to_sync_status)?;
    let mut delta = AccountSyncState {
        header,
        storage_header,
        maps: BTreeMap::new(),
        vault: BTreeMap::new(),
    };
    // Page queries take an inclusive range; the client's starting block is exclusive.
    let range = target.range_from(from.child()).map_err(database_error_to_sync_status)?;
    let maps =
        queries::account_storage_map_updates_page(tx, account, range.clone(), &None, entry_limit)
            .map_err(database_error_to_sync_status)?;
    // More map entries remain than the delta budget allows; return a snapshot instead.
    if maps.next_cursor.is_some() {
        return Ok(None);
    }

    let remaining = entry_limit.get() - maps.values.len();
    let vault = queries::account_vault_updates_page(
        tx,
        account,
        range,
        &None,
        NonZeroUsize::new(remaining).unwrap_or(NonZeroUsize::MIN),
    )
    .map_err(database_error_to_sync_status)?;
    // A continuation exceeds the remaining budget, as does any vault entry when none remains.
    // Either case requires a snapshot.
    if vault.next_cursor.is_some() || vault.values.len() > remaining {
        return Ok(None);
    }

    for entry in maps.values {
        delta.maps.entry(entry.slot_name).or_default().insert(entry.key, entry.value);
    }
    delta.vault = vault
        .values
        .into_iter()
        .map(|entry| {
            (
                entry.vault_key,
                entry.asset.map_or(Word::empty(), |asset| asset.to_value_word()),
            )
        })
        .collect();
    Ok(Some(delta))
}

fn database_error_to_sync_status(err: DatabaseError) -> Status {
    match err {
        DatabaseError::AccountNotFoundInDb(_) => Status::with_details(
            Code::NotFound,
            err.to_string(),
            vec![ErrorCode::AccountNotFound as u8].into(),
        ),
        DatabaseError::AccountNotPublic(_) => ErrorCode::AccountNotPublic.invalid_argument(err),
        DatabaseError::RangeBeyondTip(_) => ErrorCode::FutureTarget.invalid_argument(err),
        DatabaseError::BlockPruned { .. } | DatabaseError::RangeBelowRetention(_) => {
            ErrorCode::HistoryUnavailable.invalid_argument(err)
        },
        _ => database_error_to_status(&err),
    }
}
