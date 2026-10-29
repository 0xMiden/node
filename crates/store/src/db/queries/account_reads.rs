use miden_node_db::sqlite::ReadTx;
use miden_node_proto::domain::account::AccountSyncState;
use miden_protocol::Word;
use miden_protocol::account::{AccountCode, AccountHeader, AccountId, AccountStorageHeader};

use super::{
    check_account_history_target,
    load_full_account_at,
    select_account_code_by_commitment,
    select_account_header_with_storage_header_at_block,
    select_account_size,
};
use crate::{AccountSize, DatabaseError, ScopedBlockNum};

/// Returns live public-account counts at a retained, tip-scoped block.
pub fn account_size(
    tx: &ReadTx<'_>,
    account: AccountId,
    block: ScopedBlockNum,
) -> Result<AccountSize, DatabaseError> {
    check_public_account(tx, account, block)?;
    select_account_size(tx, account, *block)?.ok_or(DatabaseError::AccountNotFoundInDb(account))
}

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

/// Returns complete public-account state at a retained, tip-scoped block without loading code.
pub fn account_state(
    tx: &ReadTx<'_>,
    account: AccountId,
    block: ScopedBlockNum,
) -> Result<AccountSyncState, DatabaseError> {
    check_public_account(tx, account, block)?;
    load_full_account_at(tx, account, *block)
}

/// Returns account code by commitment from the supplied database snapshot.
pub fn account_code(
    tx: &ReadTx<'_>,
    commitment: Word,
) -> Result<Option<AccountCode>, DatabaseError> {
    select_account_code_by_commitment(tx, commitment)?
        .map(|bytes| miden_node_persistence::decode(&bytes).map_err(DatabaseError::from))
        .transpose()
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
