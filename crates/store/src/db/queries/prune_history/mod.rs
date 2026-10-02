//! Deletes account history that can no longer serve a read inside the retention window.

use miden_node_db::sqlite::WriteTx;
use miden_node_tracing::miden_instrument;
use miden_protocol::block::BlockNumber;

use crate::COMPONENT;
use crate::db::queries::VALID_FOREVER;
use crate::errors::DatabaseError;

const SQL_VAULT_ASSETS: &str = include_str!("prune_account_vault_assets.sql");
const SQL_STORAGE_MAP_VALUES: &str = include_str!("prune_account_storage_map_values.sql");
const SQL_ACCOUNT_CODES_FULL: &str = include_str!("prune_account_codes_full.sql");
const SQL_ACCOUNT_CODES_WINDOWED: &str = include_str!("prune_account_codes_windowed.sql");
const SQL_SELECT_PRUNE_PROGRESS: &str = include_str!("select_prune_progress.sql");
const SQL_UPSERT_PRUNE_PROGRESS: &str = include_str!("upsert_prune_progress.sql");

/// The two pruning statements spell the open-ended sentinel out as a literal so SQLite can match it
/// against the partial cleanup indexes; that literal has to stay in step with [`VALID_FOREVER`].
const _: () = assert!(
    VALID_FOREVER == 9_223_372_036_854_775_807,
    "the `valid_until != <sentinel>` literal in the pruning statements is out of date"
);

/// Number of historical blocks to retain for vault assets, storage map values, and account codes.
/// Rows whose validity interval ends at or below `prune_tip - HISTORICAL_BLOCK_RETENTION` will be
/// deleted; rows still valid anywhere inside the retention window (including all open-ended rows)
/// are retained.
pub const HISTORICAL_BLOCK_RETENTION: u32 = 50;

/// Clean up old entries for all accounts, deleting entries that can no longer affect state
/// reconstruction at any block within the retention window.
///
/// A row is applicable for blocks in `[block_num, valid_until)`, so it is deletable exactly when
/// its interval ends at or below the cutoff (`prune_tip - HISTORICAL_BLOCK_RETENTION`): it then
/// cannot cover any block inside the window. `prune_tip` is the effective tip for retention — it
/// lags the chain tip while old snapshot generations are still pinned by readers (see
/// [`crate::db::Db::apply_block`]). Account codes follow the same rule — a code is deleted only
/// when no account row whose interval reaches past the cutoff references it.
///
/// # Returns
/// A tuple of `(vault_assets_deleted, storage_map_values_deleted, account_codes_deleted)`
#[miden_instrument(
    target = COMPONENT,
    err,
    fields(
        cutoff_block,
    ),
)]
pub(crate) fn prune_history(
    tx: &WriteTx<'_>,
    prune_tip: BlockNumber,
) -> Result<(usize, usize, usize), DatabaseError> {
    let cutoff_block = i64::from(prune_tip.as_u32().saturating_sub(HISTORICAL_BLOCK_RETENTION));
    miden_node_tracing::Span::current().record("cutoff_block", cutoff_block);

    let vault_deleted = tx.execute(SQL_VAULT_ASSETS, &[&cutoff_block])?;
    let storage_deleted = tx.execute(SQL_STORAGE_MAP_VALUES, &[&cutoff_block])?;
    let codes_deleted = prune_account_codes(tx, cutoff_block)?;

    Ok((vault_deleted, storage_deleted, codes_deleted))
}

/// Deletes account codes that are no longer referenced by any account row that can serve a read
/// within the retention window.
///
/// An account code is safe to delete when no `accounts` row whose validity interval reaches past
/// the cutoff (`valid_until > cutoff_block`) references it. That single predicate covers rows
/// inside the window, all open-ended (current) rows, and each account's baseline row — the row
/// still valid at the cutoff even though it was written before it.
///
/// Rather than re-checking every code on every prune, only codes whose deletability could have
/// changed since the previous prune are examined. A code survived the previous prune because at
/// least one `accounts` row with `valid_until > prev_cutoff` referenced it. For it to be
/// deletable now, all such rows must have expired by the new cutoff — including the longest-lived
/// one, whose `valid_until` therefore lands inside `(prev_cutoff, cutoff_block]`. Scanning the
/// rows that expired in that window thus finds every code that could have become deletable. The
/// previous cutoff is persisted in `prune_progress` within the same transaction; when absent
/// (first prune after migration, or a fresh database) a full pass over all rows valid past the
/// cutoff runs instead.
///
/// Correctness of the windowed candidate set rests on two invariants:
/// - Rows are only ever closed to the `block_num` of the block currently being applied, which is
///   always above the cutoff, so every expiry crosses the window of some later prune. A write path
///   that back-dated `valid_until` below the current cutoff would leak the code forever.
/// - Every `account_codes` row is inserted alongside an `accounts` row referencing it (see
///   [`upsert_accounts`](super::upsert_accounts)); an orphan code with no referencing row would
///   never become a candidate.
#[miden_instrument(
    target = COMPONENT,
    err,
    fields(
        cutoff_block,
    ),
)]
fn prune_account_codes(tx: &WriteTx<'_>, cutoff_block: i64) -> Result<usize, DatabaseError> {
    let prev_cutoff = tx
        .query(SQL_SELECT_PRUNE_PROGRESS, &[], |row| row.get::<i64>(0))?
        .into_iter()
        .next();

    let deleted = match prev_cutoff {
        // Codes are already pruned through this cutoff and nothing can become collectable while the
        // cutoff stands still. Equality is the common case: the cutoff is clamped to zero for the
        // first `HISTORICAL_BLOCK_RETENTION` blocks, and a pinned snapshot freezes the prune tip
        // across consecutive blocks. A strictly greater `prev_cutoff` is unreachable through
        // `apply_block` (the prune tip never regresses) but is guarded against so an out-of-order
        // caller cannot move the marker backwards or run the delete with an inverted window.
        Some(prev_cutoff) if prev_cutoff >= cutoff_block => return Ok(0),
        Some(prev_cutoff) => {
            tx.execute(SQL_ACCOUNT_CODES_WINDOWED, &[&prev_cutoff, &cutoff_block])?
        },
        None => tx.execute(SQL_ACCOUNT_CODES_FULL, &[&cutoff_block])?,
    };

    tx.execute(SQL_UPSERT_PRUNE_PROGRESS, &[&cutoff_block])?;

    Ok(deleted)
}
