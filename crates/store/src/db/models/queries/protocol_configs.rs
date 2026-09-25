use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SqliteConnection};
use miden_protocol::Word;
use miden_protocol::block::BlockNumber;
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::utils::serde::{ByteReader, Deserializable, Serializable, SliceReader};

use crate::db::schema::protocol_configs;
use crate::errors::DatabaseError;

/// Selects a protocol configuration by its commitment.
pub(crate) fn select_protocol_config_by_commitment(
    conn: &mut SqliteConnection,
    commitment: Word,
) -> Result<Option<ProtocolConfig>, DatabaseError> {
    let bytes = protocol_configs::table
        .filter(protocol_configs::commitment.eq(commitment.to_bytes()))
        .select(protocol_configs::protocol_config)
        .order(protocol_configs::block_number.asc())
        .first::<Vec<u8>>(conn)
        .optional()?;

    let Some(bytes) = bytes else {
        return Ok(None);
    };

    let mut reader = SliceReader::new(&bytes);
    let protocol_config = ProtocolConfig::read_from(&mut reader)?;
    if reader.has_more_bytes() {
        return Err(DatabaseError::DataCorrupted(format!(
            "protocol config {commitment} has trailing bytes"
        )));
    }
    let calculated = protocol_config.to_commitment();
    if calculated != commitment {
        return Err(DatabaseError::ProtocolConfigCommitmentMismatch {
            expected: commitment,
            calculated,
        });
    }

    Ok(Some(protocol_config))
}

/// Selects the configuration commitment active at the specified block.
pub(crate) fn select_protocol_config_commitment_at(
    conn: &mut SqliteConnection,
    block_number: BlockNumber,
) -> Result<Option<Word>, DatabaseError> {
    let bytes = protocol_configs::table
        .filter(protocol_configs::block_number.le(i64::from(block_number.as_u32())))
        .order(protocol_configs::block_number.desc())
        .select(protocol_configs::commitment)
        .first::<Vec<u8>>(conn)
        .optional()?;
    bytes.map(|bytes| Word::read_from_bytes(&bytes).map_err(Into::into)).transpose()
}

#[cfg(test)]
mod tests {
    use miden_node_utils::fee::test_protocol_config;
    use miden_protocol::Word;
    use miden_protocol::block::BlockNumber;
    use miden_protocol::protocol_config::ProtocolConfig;
    use miden_protocol::utils::serde::Serializable;

    use super::{select_protocol_config_by_commitment, select_protocol_config_commitment_at};
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

    #[test]
    fn inserts_and_selects_protocol_config() {
        let db = TestDb::new();
        let config = test_protocol_config();
        let commitment = config.to_commitment();

        insert_protocol_config(&db, &config, 0.into()).unwrap();

        assert_eq!(
            select_protocol_config_by_commitment(&mut db.diesel_conn(), commitment).unwrap(),
            Some(config)
        );
    }

    #[test]
    fn returns_none_for_unknown_commitment() {
        let db = TestDb::new();

        assert_eq!(
            select_protocol_config_by_commitment(&mut db.diesel_conn(), Word::empty()).unwrap(),
            None
        );
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

        let mut conn = db.diesel_conn();
        assert_eq!(
            select_protocol_config_by_commitment(&mut conn, first.to_commitment()).unwrap(),
            Some(first)
        );
        assert_eq!(
            select_protocol_config_by_commitment(&mut conn, second.to_commitment()).unwrap(),
            Some(second)
        );
    }

    #[test]
    fn selects_commitment_at_activation_boundaries() {
        let db = TestDb::new();
        let mut conn = db.diesel_conn();
        let first = test_protocol_config();
        let second = ProtocolConfig::current(miden_protocol::asset::AssetId::new_fungible(
            miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        assert_ne!(first.to_commitment(), second.to_commitment());
        assert_eq!(select_protocol_config_commitment_at(&mut conn, 0.into()).unwrap(), None);
        for (height, config) in [(0, &first), (3, &second), (7, &first)] {
            insert_protocol_config(&db, config, height.into()).unwrap();
        }
        for (height, config) in
            [(0, &first), (2, &first), (3, &second), (6, &second), (7, &first), (9, &first)]
        {
            assert_eq!(
                select_protocol_config_commitment_at(&mut conn, height.into()).unwrap(),
                Some(config.to_commitment())
            );
        }
        assert_eq!(
            select_protocol_config_by_commitment(&mut conn, first.to_commitment()).unwrap(),
            Some(first.clone())
        );
        assert!(insert_protocol_config(&db, &first, 7.into()).is_err());
        assert!(insert_protocol_config(&db, &second, 7.into()).is_err());
    }

    #[test]
    fn rejects_a_row_stored_under_the_wrong_commitment() {
        let db = TestDb::new();
        let config = test_protocol_config();
        let expected = Word::empty();
        let calculated = config.to_commitment();
        insert_raw_protocol_config(&db, expected, config.to_bytes());

        assert!(matches!(
            select_protocol_config_by_commitment(&mut db.diesel_conn(), expected),
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

        let mut conn = db.diesel_conn();
        assert_eq!(
            select_protocol_config_commitment_at(&mut conn, 0.into()).unwrap(),
            Some(commitment)
        );
        assert!(matches!(
            select_protocol_config_by_commitment(&mut conn, commitment),
            Err(DatabaseError::DeserializationError(_))
        ));
    }

    #[test]
    fn rejects_trailing_serialized_bytes() {
        let db = TestDb::new();
        let config = test_protocol_config();
        let commitment = config.to_commitment();
        let mut bytes = config.to_bytes();
        bytes.push(0xff);
        insert_raw_protocol_config(&db, commitment, bytes);

        assert!(matches!(
            select_protocol_config_by_commitment(&mut db.diesel_conn(), commitment),
            Err(DatabaseError::DataCorrupted(_))
        ));
    }
}
