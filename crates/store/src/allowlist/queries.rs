use std::time::{SystemTime, UNIX_EPOCH};

use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SqliteConnection};
use miden_protocol::account::AccountId;
use miden_protocol::utils::serde::{Deserializable, Serializable};

use super::schema::account_allowlist;
use super::{
    AllowlistError,
    InvitationCode,
    InvitationEntry,
    InvitationStatus,
    RegistrationOutcome,
};
use crate::DatabaseError;

pub(super) fn contains_account(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<bool, DatabaseError> {
    let query =
        account_allowlist::table.filter(account_allowlist::account_id.eq(account_id.to_bytes()));
    diesel::select(diesel::dsl::exists(query))
        .get_result(conn)
        .map_err(DatabaseError::Diesel)
}

pub(super) fn invitation_status(
    conn: &mut SqliteConnection,
    invitation: &InvitationCode,
) -> Result<InvitationStatus, DatabaseError> {
    let account = account_allowlist::table
        .filter(account_allowlist::invitation_digest.eq(invitation.digest()))
        .select(account_allowlist::account_id)
        .first::<Option<Vec<u8>>>(conn)
        .optional()
        .map_err(DatabaseError::Diesel)?;

    Ok(match account {
        None => InvitationStatus::Unknown,
        Some(None) => InvitationStatus::Unused,
        Some(Some(bytes)) => InvitationStatus::Registered(
            AccountId::read_from_bytes(&bytes).map_err(DatabaseError::DeserializationError)?,
        ),
    })
}

pub(super) fn add_account(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<usize, DatabaseError> {
    diesel::insert_into(account_allowlist::table)
        .values((
            account_allowlist::account_id.eq(account_id.to_bytes()),
            account_allowlist::created_at.eq(current_timestamp()),
        ))
        .on_conflict(account_allowlist::account_id)
        .do_nothing()
        .execute(conn)
        .map_err(DatabaseError::Diesel)
}

pub(super) fn import_invitation(
    conn: &mut SqliteConnection,
    entry: &InvitationEntry,
) -> Result<(), AllowlistError> {
    match invitation_status(conn, &entry.invitation_code).map_err(AllowlistError::Database)? {
        InvitationStatus::Unknown => {
            if let Some(account_id) = entry.account_id {
                ensure_account_unregistered(conn, account_id)?;
            }
            diesel::insert_into(account_allowlist::table)
                .values((
                    account_allowlist::invitation_digest.eq(entry.invitation_code.digest()),
                    account_allowlist::account_id.eq(entry.account_id.map(|id| id.to_bytes())),
                    account_allowlist::created_at.eq(current_timestamp()),
                ))
                .execute(conn)
                .map_err(|error| AllowlistError::Database(DatabaseError::Diesel(error)))?;
        },
        InvitationStatus::Unused => {
            if let Some(account_id) = entry.account_id {
                bind_invitation(conn, &entry.invitation_code, account_id)?;
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
    conn: &mut SqliteConnection,
    invitation: &InvitationCode,
    account_id: AccountId,
) -> Result<RegistrationOutcome, AllowlistError> {
    match invitation_status(conn, invitation).map_err(AllowlistError::Database)? {
        InvitationStatus::Unknown => Err(AllowlistError::InvitationNotFound),
        InvitationStatus::Registered(registered) if registered == account_id => {
            Ok(RegistrationOutcome::AlreadyRegistered)
        },
        InvitationStatus::Registered(_) => Err(AllowlistError::InvitationAlreadyUsed),
        InvitationStatus::Unused => {
            bind_invitation(conn, invitation, account_id)?;
            Ok(RegistrationOutcome::Registered)
        },
    }
}

fn bind_invitation(
    conn: &mut SqliteConnection,
    invitation: &InvitationCode,
    account_id: AccountId,
) -> Result<(), AllowlistError> {
    ensure_account_unregistered(conn, account_id)?;
    diesel::update(
        account_allowlist::table
            .filter(account_allowlist::invitation_digest.eq(invitation.digest())),
    )
    .set(account_allowlist::account_id.eq(account_id.to_bytes()))
    .execute(conn)
    .map_err(|error| AllowlistError::Database(DatabaseError::Diesel(error)))?;
    Ok(())
}

fn ensure_account_unregistered(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<(), AllowlistError> {
    if contains_account(conn, account_id).map_err(AllowlistError::Database)? {
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
