//! Durable funding requests and their delivery records.
//!
//! Requests remain available for auditing after delivery. The database belongs to one chain,
//! funding account, and native asset, so opening it on another network fails.

use std::num::NonZeroUsize;
use std::path::Path;
use std::time::SystemTime;

use anyhow::{Context, ensure};
use miden_node_db::sqlite::{DbReader, DbWriter};
use miden_node_utils::usdcx_p2id::UsdcxP2Id;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteId};
use miden_protocol::transaction::TransactionId;

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

    /// Stores a funding note and returns only after its transaction commits durably.
    ///
    /// Retrying the same note preserves its original acceptance order, timestamp, and delivery
    /// record. Reusing its ID with different contents fails.
    pub async fn store_request(&self, note: UsdcxP2Id) -> anyhow::Result<StoredRequest> {
        ensure!(
            note.note().metadata().sender() == self.identity.funding_account_id,
            "the note sender is not the funding account"
        );
        ensure!(
            UsdcxP2Id::from_note(note.note().clone(), self.identity.fee_asset_id).is_some(),
            "the note does not hold the configured native asset"
        );
        ensure!(note.amount() > 0, "the funding amount must not be zero");
        ensure!(note.target() != self.identity.funding_account_id, "the note targets the funder");
        let note = note.into_note();
        self.writer
            .write("store funding request", move |tx| {
                if let Some(stored) = queries::select_request(tx, note.id())? {
                    ensure!(stored.note == note, "the note ID already has different contents");
                    return Ok(stored);
                }
                queries::insert_request(tx, &note, SystemTime::now())?;
                queries::select_request(tx, note.id())?.context("the stored request is missing")
            })
            .await
    }

    /// Returns the oldest undelivered requests, bounded by the requested batch size.
    pub async fn pending_requests(
        &self,
        limit: NonZeroUsize,
    ) -> anyhow::Result<Vec<StoredRequest>> {
        let limit = i64::try_from(limit.get()).context("request batch limit exceeds i64")?;
        Ok(self
            .reader
            .read("read pending funding requests", move |tx| {
                queries::select_pending_requests(tx, limit)
            })
            .await?)
    }

    /// Returns a request for auditing, including requests already delivered.
    pub async fn request(&self, note_id: NoteId) -> anyhow::Result<Option<StoredRequest>> {
        Ok(self
            .reader
            .read("read funding request", move |tx| queries::select_request(tx, note_id))
            .await?)
    }

    /// Records a confirmed transaction for an entire batch without removing its requests.
    ///
    /// The caller must establish commitment on chain before calling this method. Missing requests
    /// or conflicting delivery records reject the whole batch. Repeating a confirmation preserves
    /// its original timestamp.
    pub async fn record_delivery(
        &self,
        notes: Vec<NoteId>,
        transaction_id: TransactionId,
        committed_in_block: BlockNumber,
    ) -> anyhow::Result<()> {
        self.writer
            .write("record funding delivery", move |tx| {
                let confirmed_at = SystemTime::now();
                for note_id in notes {
                    let stored =
                        queries::select_request(tx, note_id)?.context("unknown funding request")?;
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
                Ok(())
            })
            .await
    }
}
