//! Stores account registrations and invitation codes for the sequencer.
//!
//! The registry contains unused invitation codes, accounts registered with an invitation code, and accounts added directly.
//! Registry membership does not depend on account deployment or transaction admission policy.

use std::path::Path;

use miden_node_db::sqlite::{DbReader, DbWriter, WriteTx};
use miden_protocol::account::AccountId;
use thiserror::Error;

use crate::DatabaseError;

mod invitation;
mod migrations;
mod queries;

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

/// An invitation's registration and allowlist entry timestamp in UTC Unix seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvitationInfo {
    pub account_id: Option<AccountId>,
    pub allowlisted_at: i64,
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
    db: DbReader,
}

impl AccountAllowlistReader {
    /// Returns when the account's allowlist entry was added, if it exists.
    pub async fn allowlisted_at(
        &self,
        account_id: AccountId,
    ) -> Result<Option<i64>, DatabaseError> {
        self.db
            .read("allowlist.allowlisted_at", move |tx| queries::allowlisted_at(tx, account_id))
            .await
            .map_err(DatabaseError::DatabaseError)
    }

    /// Returns the invitation's registration and allowlist entry timestamp, if it exists.
    pub async fn invitation_info(
        &self,
        invitation_code: InvitationCode,
    ) -> Result<Option<InvitationInfo>, DatabaseError> {
        self.db
            .read("allowlist.invitation_info", move |tx| {
                queries::invitation_info(tx, &invitation_code)
            })
            .await
            .map_err(DatabaseError::DatabaseError)
    }

    /// Returns whether the registry contains the account.
    pub async fn contains_account(&self, account_id: AccountId) -> Result<bool, DatabaseError> {
        self.db
            .read("allowlist.contains_account", move |tx| {
                queries::contains_account(tx, account_id)
            })
            .await
            .map_err(DatabaseError::DatabaseError)
    }

    /// Returns the registration state of the invitation code.
    pub async fn invitation_status(
        &self,
        invitation_code: InvitationCode,
    ) -> Result<InvitationStatus, DatabaseError> {
        self.db
            .read("allowlist.invitation_status", move |tx| {
                queries::invitation_status(tx, &invitation_code)
            })
            .await
            .map_err(DatabaseError::DatabaseError)
    }
}

/// Persistent account registry in a separate SQLite database.
///
/// The registry has separate reader and writer pools. Its writes do not wait for block database writes.
/// Each entry records when it was added to the allowlist in UTC Unix seconds. Registration and retries preserve this time.
/// Write transactions acquire the write lock before they read registrations.
/// Each write operation commits all its changes together. Failed operations leave no changes.
pub struct AccountAllowlist {
    writer: DbWriter,
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
        let (writer, reader) =
            miden_node_db::sqlite::open(database_filepath).map_err(DatabaseError::DatabaseError)?;
        Ok(Self {
            writer,
            reader: AccountAllowlistReader { db: reader },
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

    /// Returns a read-only handle that shares the reader pool.
    pub fn reader(&self) -> AccountAllowlistReader {
        self.reader.clone()
    }

    /// Imports an invitation code with an optional account registration.
    /// Returns true if the invitation entry is new.
    ///
    /// An entry without an account preserves any existing registration for its invitation code.
    /// An entry with an account can register an unused invitation code. An identical registration has no effect.
    /// A conflicting registration leaves the registry unchanged.
    pub async fn import_invitation(&self, entry: InvitationEntry) -> Result<bool, AllowlistError> {
        self.transact("allowlist.import_invitation", move |tx| {
            queries::import_invitation(tx, &entry)
        })
        .await
    }

    /// Adds an account without an invitation code. Returns true if the registration is new.
    ///
    /// An existing account keeps its invitation code registration, if any.
    pub async fn add_account(&self, account_id: AccountId) -> Result<bool, DatabaseError> {
        self.writer
            .write("allowlist.add_account", move |tx| queries::add_account(tx, account_id))
            .await
            .map_err(DatabaseError::DatabaseError)
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
        self.transact("allowlist.register_account", move |tx| {
            queries::register_account(tx, &invitation_code, account_id)
        })
        .await
    }

    async fn transact<T: Send + 'static>(
        &self,
        name: &'static str,
        query: impl FnOnce(&WriteTx<'_>) -> Result<T, AllowlistError> + Send + 'static,
    ) -> Result<T, AllowlistError> {
        let tx = self
            .writer
            .begin_write()
            .await
            .map_err(DatabaseError::DatabaseError)
            .map_err(AllowlistError::Database)?;
        let result = tx
            .run(name, move |tx| Ok::<_, miden_node_db::DatabaseError>(query(tx)))
            .await
            .map_err(DatabaseError::DatabaseError)
            .map_err(AllowlistError::Database)
            .and_then(std::convert::identity);

        match result {
            Ok(value) => {
                tx.commit()
                    .await
                    .map_err(DatabaseError::DatabaseError)
                    .map_err(AllowlistError::Database)?;
                Ok(value)
            },
            Err(error) => {
                tx.rollback()
                    .await
                    .map_err(DatabaseError::DatabaseError)
                    .map_err(AllowlistError::Database)?;
                Err(error)
            },
        }
    }
}
