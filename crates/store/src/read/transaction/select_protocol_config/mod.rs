use miden_protocol::Word;
use miden_protocol::protocol_config::ProtocolConfig;

use super::ReadTransaction;
use crate::DatabaseError;

const SQL: &str = include_str!("query.sql");

impl ReadTransaction<'_> {
    /// Returns the configuration stored under `commitment` in this transaction's snapshot.
    ///
    /// Decoding verifies that the stored configuration hashes to the requested commitment.
    pub fn select_protocol_config(
        &self,
        commitment: Word,
    ) -> Result<Option<ProtocolConfig>, DatabaseError> {
        // Read the raw bytes and decode them here, so that a corrupt row returns
        // `DatabaseError::Persistence`.
        let Some(bytes) = self
            .inner
            .query(SQL, &[&commitment], |row| row.get::<Vec<u8>>(0))?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };

        let protocol_config: ProtocolConfig = miden_node_persistence::decode(&bytes)?;
        let calculated = protocol_config.to_commitment();
        if calculated != commitment {
            return Err(DatabaseError::ProtocolConfigCommitmentMismatch {
                expected: commitment,
                calculated,
            });
        }

        Ok(Some(protocol_config))
    }
}

#[cfg(test)]
mod tests;
