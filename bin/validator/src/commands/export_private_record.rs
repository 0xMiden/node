use anyhow::Context;
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::serde::Deserializable;
use miden_validator::{DataDirectory, PrivateRecordId};

use super::PrivateRecordExportOptions;

/// Exports one validator-qualified private-record bundle.
pub(super) async fn export(options: PrivateRecordExportOptions) -> anyhow::Result<()> {
    let PrivateRecordExportOptions {
        data_directory,
        transaction_id,
        validator_id,
        output,
    } = options;
    let record_id = parse_record_id(&transaction_id, &validator_id)?;
    let data_directory =
        DataDirectory::load(data_directory).context("failed to load validator data directory")?;
    let db = miden_validator::db::load(data_directory.database_path())
        .await
        .context("failed to load validator database")?;
    let transaction_id = record_id.transaction_id();
    let record = db
        .load_private_record(transaction_id)
        .await
        .context("failed to load private record")?
        .filter(|record| record.record_id() == record_id)
        .with_context(|| {
            format!("private record ({transaction_id}, {validator_id}) was not found")
        })?;

    fs_err::write(&output, miden_node_persistence::encode(&record))
        .with_context(|| format!("failed to write private record bundle to {}", output.display()))
}

/// Parses one validator-qualified private-record identity.
fn parse_record_id(
    encoded_transaction_id: &str,
    encoded_validator_id: &str,
) -> anyhow::Result<PrivateRecordId> {
    let transaction_id = parse_transaction_id(encoded_transaction_id)?;
    let validator_id =
        hex::decode(encoded_validator_id).context("validator id is not valid hex")?;
    let actual = validator_id.len();
    let validator_id = validator_id
        .try_into()
        .map_err(|_: Vec<u8>| anyhow::anyhow!("validator id has {actual} bytes, expected 33"))?;
    PrivateRecordId::from_parts(transaction_id, validator_id)
        .context("validator id is not a canonical signing public key")
}

/// Parses one canonical transaction identifier.
fn parse_transaction_id(encoded: &str) -> anyhow::Result<TransactionId> {
    let bytes = hex::decode(encoded).context("transaction id is not valid hex")?;
    let actual = bytes.len();
    anyhow::ensure!(actual == 32, "transaction id has {actual} bytes, expected 32");
    TransactionId::read_from_bytes(&bytes).context("transaction id is not canonical")
}
