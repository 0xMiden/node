use rusqlite::Transaction;

/// Assigns a database nonce without changing notes or storage counters.
pub fn migrate(tx: &Transaction<'_>) -> anyhow::Result<()> {
    tx.execute_batch(
        "CREATE TABLE storage_metadata_with_nonce (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            retained_bytes INTEGER NOT NULL CHECK (retained_bytes >= 0),
            nonce BLOB NOT NULL CHECK (length(nonce) = 8)
        ) STRICT;",
    )?;
    let nonce = rand::random::<u64>().to_le_bytes();
    tx.execute(
        "INSERT INTO storage_metadata_with_nonce (singleton, retained_bytes, nonce)
         SELECT singleton, retained_bytes, ?1 FROM storage_metadata",
        [nonce.as_slice()],
    )?;
    tx.execute_batch(
        "DROP TABLE storage_metadata;
         ALTER TABLE storage_metadata_with_nonce RENAME TO storage_metadata;",
    )?;
    Ok(())
}
