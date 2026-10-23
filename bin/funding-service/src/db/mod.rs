//! Durable funding requests and their delivery records.
//!
//! Requests remain available for auditing after delivery. The database belongs to one chain,
//! funding account, and native asset, so opening it on another network fails.

use std::num::NonZeroUsize;
use std::path::Path;
use std::time::SystemTime;

use anyhow::{Context, ensure};
use miden_node_db::DatabaseError;
use miden_node_db::sqlite::{DbReader, DbWriter};
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::asset::{AssetId, FungibleAsset};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteId, NoteType, Nullifier};
use miden_protocol::transaction::TransactionId;
use miden_standards::note::P2idNote;

include!(concat!(env!("OUT_DIR"), "/db_migrator.rs"));

mod queries;

#[cfg(test)]
mod tests;

/// The chain and wallet whose requests a database contains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatabaseIdentity {
    pub genesis_commitment: Word,
    pub funding_account_id: AccountId,
    pub fee_asset_id: AssetId,
}

impl DatabaseIdentity {
    /// Builds a public P2ID note using the database's sender and native asset.
    fn build_note(
        self,
        target: AccountId,
        amount: u64,
        serial_number: Word,
    ) -> Result<Note, DatabaseError> {
        let asset = FungibleAsset::new(self.fee_asset_id.faucet_id(), amount)
            .map_err(|err| DatabaseError::deserialization("funding asset", err))?;
        P2idNote::builder()
            .sender(self.funding_account_id)
            .target(target)
            .asset(asset)
            .note_type(NoteType::Public)
            .serial_number(serial_number)
            .build()
            .map(Note::from)
            .map_err(|err| DatabaseError::deserialization("funding note", err))
    }
}

/// A confirmed delivery and the time the service recorded it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub transaction_id: TransactionId,
    pub committed_in_block: BlockNumber,
    /// Local time when the service recorded the transaction's commitment.
    pub confirmed_at: SystemTime,
}

/// A retained request in acceptance order, with its delivery record if confirmed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRequest {
    pub sequence: i64,
    pub note: Note,
    /// Local time when the service accepted the request.
    pub accepted_at: SystemTime,
    pub delivery: Option<Delivery>,
}

/// Describes a funding transaction and its contents.
///
/// We retain this record until we confirm that the transaction committed, expired, or was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionAttempt {
    pub transaction_id: TransactionId,
    pub reference_block: BlockNumber,
    pub expiration_block: BlockNumber,
    /// The nullifier of the deposit consumed by the transaction, if any.
    pub deposit_nullifier: Option<Nullifier>,
    pub note_ids: Vec<NoteId>,
}

/// File-backed storage for funding requests, with serialized durable writes.
pub struct FundingDatabase {
    writer: DbWriter,
    reader: DbReader,
    identity: DatabaseIdentity,
}

impl FundingDatabase {
    /// Creates a database with the current schema and binds it to the supplied identity.
    ///
    /// The path must not exist. A failed initialization leaves the file available for inspection;
    /// opening a database whose identity was not committed fails.
    pub async fn bootstrap(path: &Path, identity: DatabaseIdentity) -> anyhow::Result<Self> {
        let migrator = migrator()?;
        migrator.create_database(path)?.migrate_to(migrator.latest_version())?;
        let database = Self::handles(path, identity)?;
        database
            .writer
            .write("initialize funding database", move |tx| {
                queries::insert_database_identity(tx, &identity)
            })
            .await?;
        Ok(database)
    }

    /// Opens an existing database after verifying its schema and network identity.
    ///
    /// The stored identity supplies the funding account ID. Missing databases are not created,
    /// and pending migrations must be applied explicitly.
    pub async fn open_and_verify(
        path: &Path,
        genesis_commitment: Word,
        fee_asset_id: AssetId,
    ) -> anyhow::Result<Self> {
        migrator()?.verify_latest_schema(path)?;
        let (writer, reader) = miden_node_db::sqlite::open(path)?;
        let identity = reader
            .read("read funding database identity", queries::select_database_identity)
            .await?
            .context("funding database identity is missing")?;
        ensure!(
            identity.genesis_commitment == genesis_commitment
                && identity.fee_asset_id == fee_asset_id,
            "funding database network identity mismatch",
        );
        Ok(Self { writer, reader, identity })
    }

    /// The network and funding account recorded during bootstrap.
    pub fn identity(&self) -> DatabaseIdentity {
        self.identity
    }

    /// Applies pending migrations to an existing database while the service is stopped.
    pub fn migrate(path: &Path) -> anyhow::Result<()> {
        let migrator = migrator()?;
        migrator.open_database(path)?.migrate_to(migrator.latest_version())
    }

    fn handles(path: &Path, identity: DatabaseIdentity) -> anyhow::Result<Self> {
        migrator()?.verify_latest_schema(path)?;
        let (writer, reader) = miden_node_db::sqlite::open(path)?;
        Ok(Self { writer, reader, identity })
    }

    /// Creates and stores a funding note, returning only after its transaction commits durably.
    ///
    /// Retrying the same target, amount, and serial number preserves the original acceptance order,
    /// timestamp, and delivery record.
    pub async fn store_request(
        &self,
        target: AccountId,
        amount: u64,
        serial_number: Word,
    ) -> anyhow::Result<StoredRequest> {
        ensure!(amount > 0, "the funding amount must not be zero");
        ensure!(target != self.identity.funding_account_id, "the note targets the funder");
        let identity = self.identity;
        let note = identity.build_note(target, amount, serial_number)?;
        self.writer
            .write("store funding request", move |tx| {
                if let Some(stored) = queries::select_request(tx, note.id(), identity)? {
                    return Ok(stored);
                }
                queries::insert_request(
                    tx,
                    note.id(),
                    target,
                    amount,
                    serial_number,
                    SystemTime::now(),
                )?;
                queries::select_request(tx, note.id(), identity)?
                    .context("the stored request is missing")
            })
            .await
    }

    /// Returns up to `limit` pending requests, oldest first.
    ///
    /// Requests in a transaction awaiting confirmation are excluded.
    pub async fn pending_requests(
        &self,
        limit: NonZeroUsize,
    ) -> anyhow::Result<Vec<StoredRequest>> {
        let limit = i64::try_from(limit.get()).context("request batch limit exceeds i64")?;
        let identity = self.identity;
        Ok(self
            .reader
            .read("read pending funding requests", move |tx| {
                queries::select_pending_requests(tx, limit, identity)
            })
            .await?)
    }

    /// Returns a request for auditing, including requests already delivered.
    pub async fn request(&self, note_id: NoteId) -> anyhow::Result<Option<StoredRequest>> {
        let identity = self.identity;
        Ok(self
            .reader
            .read("read funding request", move |tx| queries::select_request(tx, note_id, identity))
            .await?)
    }

    /// Records a transaction and the requests it will create.
    ///
    /// Only one transaction can be waiting for confirmation at a time, so this fails if another
    /// attempt is recorded.
    pub async fn start_attempt(&self, attempt: TransactionAttempt) -> anyhow::Result<()> {
        ensure!(
            attempt.expiration_block > attempt.reference_block,
            "invalid attempt block range"
        );
        ensure!(
            !attempt.note_ids.is_empty() || attempt.deposit_nullifier.is_some(),
            "a funding attempt must contain requests or a deposit"
        );
        self.writer
            .write("record funding transaction attempt", move |tx| {
                queries::insert_attempt(tx, &attempt)?;
                for note_id in attempt.note_ids {
                    ensure!(
                        queries::assign_request_to_attempt(tx, note_id, attempt.transaction_id)?
                            == 1,
                        "the request is missing, already delivered, or part of an attempt"
                    );
                }
                Ok(())
            })
            .await
    }

    /// Returns the transaction we are waiting to confirm, if any.
    pub async fn active_attempt(&self) -> anyhow::Result<Option<TransactionAttempt>> {
        Ok(self.reader.read("read active funding attempt", queries::select_attempt).await?)
    }

    /// Removes a rejected or expired transaction so its requests can be retried.
    pub async fn release_attempt(&self, transaction_id: TransactionId) -> anyhow::Result<()> {
        self.writer
            .write("release funding transaction attempt", move |tx| {
                if let Some(attempt) = queries::select_attempt(tx)? {
                    ensure!(attempt.transaction_id == transaction_id, "another attempt is active");
                    queries::delete_attempt(tx, transaction_id)?;
                }
                Ok(())
            })
            .await
    }

    /// Records delivery of the requests and removes the attempt.
    ///
    /// The caller must check that the transaction committed on chain. Both updates share a database
    /// transaction so a restart cannot leave delivered requests waiting to be retried.
    pub async fn record_delivery(
        &self,
        notes: Vec<NoteId>,
        transaction_id: TransactionId,
        committed_in_block: BlockNumber,
    ) -> anyhow::Result<()> {
        let identity = self.identity;
        self.writer
            .write("record funding delivery", move |tx| {
                let attempt = queries::select_attempt(tx)?;
                if let Some(attempt) = &attempt {
                    ensure!(attempt.transaction_id == transaction_id, "another attempt is active");
                    ensure!(attempt.note_ids == notes, "the delivery does not match the attempt");
                    ensure!(
                        attempt.reference_block < committed_in_block
                            && committed_in_block <= attempt.expiration_block,
                        "the commitment is outside the attempt's block range"
                    );
                }
                let confirmed_at = SystemTime::now();
                for note_id in notes {
                    let stored = queries::select_request(tx, note_id, identity)?
                        .context("unknown funding request")?;
                    if let Some(delivery) = stored.delivery {
                        ensure!(
                            delivery.transaction_id == transaction_id
                                && delivery.committed_in_block == committed_in_block,
                            "the request already has a different delivery record"
                        );
                        continue;
                    }
                    queries::update_request_delivery(
                        tx,
                        note_id,
                        transaction_id,
                        committed_in_block,
                        confirmed_at,
                    )?;
                }
                if attempt.is_some() {
                    queries::delete_attempt(tx, transaction_id)?;
                }
                Ok(())
            })
            .await
    }
}
