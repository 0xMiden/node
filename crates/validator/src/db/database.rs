use std::path::Path;

use miden_protocol::transaction::{TransactionHeader, TransactionId};

use crate::db::DatabaseError;
use crate::db::kv_conv::{ToKey, ToValue};

/// Validator database for storing validated transaction data.
///
/// Transaction data stored in this database is intended to allow for the validation of proposed
/// blocks. All transactions in proposed blocks are expected to have been validated and stored in
/// this database before the proposed block has been received.
pub struct Database {
    /// The underlying key-value database.
    _db: fjall::Database,

    /// The "namespace" that all transaction data is stored in.
    keyspace: fjall::Keyspace,
}

impl Database {
    /// Creates a new key-value database in the specified directory.
    pub fn new(dir: &Path) -> Result<Self, DatabaseError> {
        let db = fjall::Database::builder(dir.join("validator")).open()?;
        let keyspace = db.keyspace("transactions", fjall::KeyspaceCreateOptions::default)?;

        Ok(Self { _db: db, keyspace })
    }

    /// Stores a transaction header into the database.
    pub fn put(&self, validated_tx_header: &TransactionHeader) -> Result<(), DatabaseError> {
        self.keyspace
            .insert(validated_tx_header.id().to_key(), validated_tx_header.to_value())?;
        Ok(())
    }

    /// Retrieves a transaction headers corresponding to the transaction ids from the database.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any requested transactions are not found.
    /// - Retrieved transactions cannot be deserialized.
    pub fn get(&self, ids: &[TransactionId]) -> Result<Vec<TransactionHeader>, DatabaseError> {
        let mut txs = Vec::with_capacity(ids.len());
        let mut txs_not_found = Vec::new();
        for id in ids {
            let value = self.keyspace.get(id.as_bytes())?;
            if let Some(value) = value {
                let tx_header = <TransactionHeader as ToValue>::from_value(value)?;
                txs.push(tx_header);
            } else {
                txs_not_found.push(*id);
            }
        }
        if txs_not_found.is_empty() {
            Ok(txs)
        } else {
            Err(DatabaseError::TransactionsNotFound(txs_not_found))
        }
    }
}
