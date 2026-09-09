//! Stores account registrations and invitation codes for the sequencer.
//!
//! The registry contains unused invitation codes, accounts registered with an invitation code, and accounts added directly.
//! Registry membership does not depend on account deployment or transaction admission policy.

use std::path::Path;

use diesel::SqliteConnection;
use diesel::result::Error as DieselError;
use miden_protocol::account::AccountId;
use thiserror::Error;

use crate::DatabaseError;

mod invitation;
mod migrations;
mod queries;
mod schema;

pub use invitation::{InvalidInvitationCode, InvitationCode};

#[cfg(test)]
mod tests;

/// An invitation code to import, with an optional account registration.
#[derive(Clone, Debug)]
pub struct InvitationEntry {
    pub invitation_code: InvitationCode,
    pub account_id: Option<AccountId>,
}

/// The registration state of an invitation code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvitationStatus {
    Unknown,
    Unused,
    Registered(AccountId),
}

/// The result of a successful registration request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationOutcome {
    Registered,
    /// The same invitation code was already registered to the same account.
    AlreadyRegistered,
}

/// A registry operation failed.
#[derive(Debug, Error)]
pub enum AllowlistError {
    #[error("invitation code does not exist")]
    InvitationNotFound,
    #[error("invitation code is already registered to another account")]
    InvitationAlreadyUsed,
    #[error("account {0} is already registered")]
    AccountAlreadyRegistered(AccountId),
    #[error("account registry database operation failed")]
    Database(#[source] DatabaseError),
}

/// Read-only access to the account registry.
#[derive(Clone)]
pub struct AccountAllowlistReader {
    db: miden_node_db::Db,
}

impl AccountAllowlistReader {
    /// Returns whether the registry contains the account.
    pub async fn contains_account(&self, account_id: AccountId) -> Result<bool, DatabaseError> {
        self.db
            .transact("allowlist.contains_account", move |conn| {
                queries::contains_account(conn, account_id)
            })
            .await
    }

    /// Returns the registration state of the invitation code.
    pub async fn invitation_status(
        &self,
        invitation_code: InvitationCode,
    ) -> Result<InvitationStatus, DatabaseError> {
        self.db
            .transact("allowlist.invitation_status", move |conn| {
                queries::invitation_status(conn, &invitation_code)
            })
            .await
    }
}

/// Persistent account registry in a separate SQLite database.
///
/// The registry has its own connection pool. Its writes do not wait for block database writes.
/// Each entry records its creation time in UTC Unix seconds. Registration and retries preserve this time.
/// Write transactions acquire the write lock before they read registrations.
/// Each write operation commits all its changes together. Failed operations leave no changes.
pub struct AccountAllowlist {
    db: miden_node_db::Db,
    reader: AccountAllowlistReader,
}

impl std::ops::Deref for AccountAllowlist {
    type Target = AccountAllowlistReader;

    fn deref(&self) -> &Self::Target {
        &self.reader
    }
}

impl AccountAllowlist {
    /// Creates the registry database and applies all migrations.
    ///
    /// The database file must not exist.
    pub fn bootstrap(database_filepath: impl AsRef<Path>) -> Result<(), DatabaseError> {
        let migrator = migrations::migrator()
            .map_err(miden_node_db::DatabaseError::migration)
            .map_err(DatabaseError::DatabaseError)?;
        migrator
            .bootstrap(database_filepath)
            .map_err(miden_node_db::DatabaseError::migration)
            .map_err(DatabaseError::DatabaseError)
    }

    /// Opens the registry database after verifying its schema.
    ///
    /// The database must exist and have the latest schema. This method does not apply migrations.
    pub fn load(database_filepath: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        let database_filepath = database_filepath.as_ref();
        let migrator = migrations::migrator()
            .map_err(miden_node_db::DatabaseError::migration)
            .map_err(DatabaseError::DatabaseError)?;
        migrator
            .verify_latest_schema(database_filepath)
            .map_err(miden_node_db::DatabaseError::migration)
            .map_err(DatabaseError::DatabaseError)?;
        let db = miden_node_db::Db::new(database_filepath).map_err(DatabaseError::DatabaseError)?;
        Ok(Self {
            reader: AccountAllowlistReader { db: db.clone() },
            db,
        })
    }

    /// Applies pending migrations to an existing registry database.
    pub fn migrate(database_filepath: impl AsRef<Path>) -> Result<(), DatabaseError> {
        let migrator = migrations::migrator()
            .map_err(miden_node_db::DatabaseError::migration)
            .map_err(DatabaseError::DatabaseError)?;
        migrator
            .migrate(database_filepath)
            .map_err(miden_node_db::DatabaseError::migration)
            .map_err(DatabaseError::DatabaseError)
    }

    /// Returns a read-only handle that shares the database pool.
    pub fn reader(&self) -> AccountAllowlistReader {
        self.reader.clone()
    }

    /// Imports invitation codes and their optional account registrations in one transaction.
    ///
    /// An entry without an account preserves any existing registration for its invitation code.
    /// An entry with an account can register an unused invitation code. An identical registration has no effect.
    /// A conflicting registration rejects the whole import.
    pub async fn import_invitations(
        &self,
        entries: Vec<InvitationEntry>,
    ) -> Result<(), AllowlistError> {
        self.transact("allowlist.import_invitations", move |conn| {
            for entry in entries {
                queries::import_invitation(conn, &entry)?;
            }
            Ok(())
        })
        .await
    }

    /// Adds accounts without invitation codes in one transaction and returns the number of new registrations.
    ///
    /// Existing accounts keep their invitation code registrations, if any.
    pub async fn add_accounts(&self, accounts: Vec<AccountId>) -> Result<usize, DatabaseError> {
        self.db
            .query("allowlist.add_accounts", move |conn| {
                conn.immediate_transaction(|conn| {
                    let mut inserted = 0;
                    for account_id in accounts {
                        inserted += queries::add_account(conn, account_id)?;
                    }
                    Ok(inserted)
                })
            })
            .await
    }

    /// Registers an unused invitation code to an account in one transaction.
    ///
    /// A retry with the same invitation code and account succeeds without changes.
    /// An account already registered by another method cannot consume an unused invitation code.
    pub async fn register_account(
        &self,
        invitation_code: InvitationCode,
        account_id: AccountId,
    ) -> Result<RegistrationOutcome, AllowlistError> {
        self.transact("allowlist.register_account", move |conn| {
            queries::register_account(conn, &invitation_code, account_id)
        })
        .await
    }

    async fn transact<T: Send + 'static>(
        &self,
        name: &'static str,
        query: impl FnOnce(&mut SqliteConnection) -> Result<T, AllowlistError> + Send + 'static,
    ) -> Result<T, AllowlistError> {
        self.db
            .query(name, move |conn| {
                let mut query_error = None;
                let result = conn.immediate_transaction(|conn| {
                    query(conn).map_err(|error| {
                        // Ask Diesel to roll back without converting the registry error.
                        query_error = Some(error);
                        DieselError::RollbackTransaction
                    })
                });
                Ok::<_, miden_node_db::DatabaseError>(match (result, query_error) {
                    (Ok(value), _) => Ok(value),
                    (Err(DieselError::RollbackTransaction), Some(error)) => Err(error),
                    // Report transaction failures even when the query also failed.
                    (Err(error), _) => Err(AllowlistError::Database(DatabaseError::Diesel(error))),
                })
            })
            .await
            .map_err(|error| AllowlistError::Database(DatabaseError::DatabaseError(error)))?
    }
}
