use miden_node_db::sqlite::ReadTx;
use miden_protocol::account::{AccountHeader, AccountId, AccountStorageHeader};

use super::{check_account_history_target, select_account_header_with_storage_header_at_block};
use crate::{DatabaseError, ScopedBlockNum};

/// Returns public-account headers at a retained, tip-scoped block without loading entries or code.
pub fn account_headers(
    tx: &ReadTx<'_>,
    account: AccountId,
    block: ScopedBlockNum,
) -> Result<(AccountHeader, AccountStorageHeader), DatabaseError> {
    check_public_account(tx, account, block)?;
    select_account_header_with_storage_header_at_block(tx, account, *block)?
        .ok_or(DatabaseError::AccountNotFoundInDb(account))
}

pub(super) fn check_public_account(
    tx: &ReadTx<'_>,
    account: AccountId,
    block: ScopedBlockNum,
) -> Result<(), DatabaseError> {
    if !account.is_public() {
        return Err(DatabaseError::AccountNotPublic(account));
    }
    check_account_history_target(tx, *block)
}
