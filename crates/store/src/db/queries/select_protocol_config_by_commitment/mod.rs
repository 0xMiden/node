//! Returns a protocol configuration by its commitment.

use miden_node_db::sqlite::ReadTx;
use miden_protocol::Word;
use miden_protocol::protocol_config::ProtocolConfig;

use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_protocol_config_by_commitment.sql");

/// Returns the protocol configuration stored under `commitment`.
///
/// # Errors
///
/// Returns [`DatabaseError::Persistence`] if the stored bytes do not decode.
/// Returns [`DatabaseError::ProtocolConfigCommitmentMismatch`] if the decoded configuration does
/// not hash to `commitment`.
pub(crate) fn select_protocol_config_by_commitment(
    tx: &ReadTx<'_>,
    commitment: Word,
) -> Result<Option<ProtocolConfig>, DatabaseError> {
    // Read the raw bytes and decode them here, so that a corrupt row returns
    // `DatabaseError::Persistence`.
    let Some(bytes) =
        tx.query(SQL, &[&commitment], |row| row.get::<Vec<u8>>(0))?.into_iter().next()
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

#[cfg(test)]
mod tests {
    use miden_node_utils::fee::test_protocol_config;
    use miden_protocol::Word;
    use miden_protocol::block::BlockNumber;
    use miden_protocol::protocol_config::ProtocolConfig;

    use crate::db::{TestDb, queries};
    use crate::errors::DatabaseError;

    fn insert_protocol_config(
        db: &TestDb,
        protocol_config: &ProtocolConfig,
        block_number: BlockNumber,
    ) -> Result<usize, DatabaseError> {
        let protocol_config = protocol_config.clone();
        db.write(move |tx| queries::insert_protocol_config(tx, &protocol_config, block_number))
    }

    /// Stores `bytes` under `commitment` at the genesis block without any validation.
    fn insert_raw_protocol_config(db: &TestDb, commitment: Word, bytes: Vec<u8>) {
        db.write(move |tx| -> Result<usize, DatabaseError> {
            Ok(tx.execute(
                "INSERT INTO protocol_configs (commitment, block_number, protocol_config) \
                 VALUES (?1, 0, ?2)",
                &[&commitment, &bytes],
            )?)
        })
        .unwrap();
    }

    fn select_protocol_config_by_commitment(
        db: &TestDb,
        commitment: Word,
    ) -> Result<Option<ProtocolConfig>, DatabaseError> {
        db.read(move |tx| queries::select_protocol_config_by_commitment(tx, commitment))
    }

    fn select_protocol_config_commitment_at(
        db: &TestDb,
        block_number: BlockNumber,
    ) -> Result<Option<Word>, DatabaseError> {
        db.read(move |tx| queries::select_protocol_config_commitment_at(tx, block_number))
    }

    #[test]
    fn inserts_and_selects_protocol_config() {
        let db = TestDb::new();
        let config = test_protocol_config();
        let commitment = config.to_commitment();

        insert_protocol_config(&db, &config, 0.into()).unwrap();

        assert_eq!(select_protocol_config_by_commitment(&db, commitment).unwrap(), Some(config));
    }

    #[test]
    fn returns_none_for_unknown_commitment() {
        let db = TestDb::new();

        assert_eq!(select_protocol_config_by_commitment(&db, Word::empty()).unwrap(), None);
    }

    #[test]
    fn selects_multiple_protocol_configs_by_commitment() {
        use miden_protocol::asset::AssetId;
        use miden_protocol::testing::account_id::{
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
        };

        let db = TestDb::new();
        let first = ProtocolConfig::current(AssetId::new_fungible(
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap(),
        ))
        .unwrap();
        let second = ProtocolConfig::current(AssetId::new_fungible(
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap(),
        ))
        .unwrap();

        insert_protocol_config(&db, &first, 0.into()).unwrap();
        insert_protocol_config(&db, &second, 1.into()).unwrap();

        assert_eq!(
            select_protocol_config_by_commitment(&db, first.to_commitment()).unwrap(),
            Some(first)
        );
        assert_eq!(
            select_protocol_config_by_commitment(&db, second.to_commitment()).unwrap(),
            Some(second)
        );
    }

    #[test]
    fn rejects_a_row_stored_under_the_wrong_commitment() {
        let db = TestDb::new();
        let config = test_protocol_config();
        let expected = Word::empty();
        let calculated = config.to_commitment();
        insert_raw_protocol_config(&db, expected, miden_node_persistence::encode(&config));

        assert!(matches!(
            select_protocol_config_by_commitment(&db, expected),
            Err(DatabaseError::ProtocolConfigCommitmentMismatch {
                expected: actual_expected,
                calculated: actual_calculated,
            }) if actual_expected == expected && actual_calculated == calculated
        ));
    }

    #[test]
    fn rejects_invalid_serialized_protocol_config() {
        let db = TestDb::new();
        let commitment = Word::empty();
        insert_raw_protocol_config(&db, commitment, vec![0xff]);

        assert_eq!(select_protocol_config_commitment_at(&db, 0.into()).unwrap(), Some(commitment));
        assert!(matches!(
            select_protocol_config_by_commitment(&db, commitment),
            Err(DatabaseError::Persistence(_))
        ));
    }

    #[test]
    fn rejects_malformed_protobuf_suffix() {
        let db = TestDb::new();
        let config = test_protocol_config();
        let commitment = config.to_commitment();
        let mut bytes = miden_node_persistence::encode(&config);
        bytes.push(0xff);
        insert_raw_protocol_config(&db, commitment, bytes);

        assert!(matches!(
            select_protocol_config_by_commitment(&db, commitment),
            Err(DatabaseError::Persistence(_))
        ));
    }
}
