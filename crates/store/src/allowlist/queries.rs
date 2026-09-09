use std::time::{SystemTime, UNIX_EPOCH};

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::{ReadTx, WriteTx};
use miden_protocol::account::AccountId;

use super::{
    AllowlistError,
    InvitationCode,
    InvitationEntry,
    InvitationStatus,
    RegistrationOutcome,
};

pub(super) fn contains_account(
    tx: &ReadTx<'_>,
    account_id: AccountId,
) -> Result<bool, DatabaseError> {
    Ok(tx
        .query(
            "SELECT EXISTS(SELECT 1 FROM account_allowlist WHERE account_id = ?1)",
            &[&account_id],
            |row| row.get::<bool>(0),
        )?
        .into_iter()
        .next()
        .unwrap_or(false))
}

pub(super) fn invitation_status(
    tx: &ReadTx<'_>,
    invitation: &InvitationCode,
) -> Result<InvitationStatus, DatabaseError> {
    let account = tx
        .query(
            "SELECT account_id FROM account_allowlist WHERE invitation_digest = ?1",
            &[&invitation.digest().to_vec()],
            |row| row.get::<Option<AccountId>>(0),
        )?
        .into_iter()
        .next();

    Ok(match account {
        None => InvitationStatus::Unknown,
        Some(None) => InvitationStatus::Unused,
        Some(Some(account)) => InvitationStatus::Registered(account),
    })
}

pub(super) fn add_account(tx: &WriteTx<'_>, account_id: AccountId) -> Result<usize, DatabaseError> {
    tx.execute(
        "INSERT INTO account_allowlist (account_id, created_at) VALUES (?1, ?2)
         ON CONFLICT(account_id) DO NOTHING",
        &[&account_id, &current_timestamp()],
    )
}

pub(super) fn import_invitation(
    tx: &WriteTx<'_>,
    entry: &InvitationEntry,
) -> Result<(), AllowlistError> {
    match invitation_status(tx, &entry.invitation_code)
        .map_err(crate::DatabaseError::DatabaseError)
        .map_err(AllowlistError::Database)?
    {
        InvitationStatus::Unknown => {
            if let Some(account_id) = entry.account_id {
                ensure_account_unregistered(tx, account_id)?;
            }
            tx.execute(
                "INSERT INTO account_allowlist (invitation_digest, account_id, created_at)
                 VALUES (?1, ?2, ?3)",
                &[
                    &entry.invitation_code.digest().to_vec(),
                    &entry.account_id,
                    &current_timestamp(),
                ],
            )
            .map_err(crate::DatabaseError::DatabaseError)
            .map_err(AllowlistError::Database)?;
        },
        InvitationStatus::Unused => {
            if let Some(account_id) = entry.account_id {
                bind_invitation(tx, &entry.invitation_code, account_id)?;
            }
        },
        InvitationStatus::Registered(account_id) => {
            if entry.account_id.is_some_and(|requested| requested != account_id) {
                return Err(AllowlistError::InvitationAlreadyUsed);
            }
        },
    }
    Ok(())
}

pub(super) fn register_account(
    tx: &WriteTx<'_>,
    invitation: &InvitationCode,
    account_id: AccountId,
) -> Result<RegistrationOutcome, AllowlistError> {
    match invitation_status(tx, invitation)
        .map_err(crate::DatabaseError::DatabaseError)
        .map_err(AllowlistError::Database)?
    {
        InvitationStatus::Unknown => Err(AllowlistError::InvitationNotFound),
        InvitationStatus::Registered(registered) if registered == account_id => {
            Ok(RegistrationOutcome::AlreadyRegistered)
        },
        InvitationStatus::Registered(_) => Err(AllowlistError::InvitationAlreadyUsed),
        InvitationStatus::Unused => {
            bind_invitation(tx, invitation, account_id)?;
            Ok(RegistrationOutcome::Registered)
        },
    }
}

fn bind_invitation(
    tx: &WriteTx<'_>,
    invitation: &InvitationCode,
    account_id: AccountId,
) -> Result<(), AllowlistError> {
    ensure_account_unregistered(tx, account_id)?;
    tx.execute(
        "UPDATE account_allowlist SET account_id = ?1 WHERE invitation_digest = ?2",
        &[&account_id, &invitation.digest().to_vec()],
    )
    .map_err(crate::DatabaseError::DatabaseError)
    .map_err(AllowlistError::Database)?;
    Ok(())
}

fn ensure_account_unregistered(
    tx: &ReadTx<'_>,
    account_id: AccountId,
) -> Result<(), AllowlistError> {
    if contains_account(tx, account_id)
        .map_err(crate::DatabaseError::DatabaseError)
        .map_err(AllowlistError::Database)?
    {
        return Err(AllowlistError::AccountAlreadyRegistered(account_id));
    }
    Ok(())
}

fn current_timestamp() -> i64 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is before the Unix epoch")
        .as_secs();
    i64::try_from(seconds).expect("Unix timestamp exceeds i64::MAX")
}
