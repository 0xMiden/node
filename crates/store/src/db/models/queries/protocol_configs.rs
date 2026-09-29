use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SqliteConnection};
use miden_protocol::Word;
use miden_protocol::block::BlockNumber;
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::utils::serde::{Deserializable, Serializable};

use crate::db::schema::protocol_configs;
use crate::errors::DatabaseError;

/// Inserts a protocol configuration at its activation block.
pub(crate) fn insert_protocol_config(
    conn: &mut SqliteConnection,
    protocol_config: &ProtocolConfig,
    block_number: BlockNumber,
) -> Result<usize, DatabaseError> {
    diesel::insert_into(protocol_configs::table)
        .values((
            protocol_configs::block_number.eq(i64::from(block_number.as_u32())),
            protocol_configs::commitment.eq(protocol_config.to_commitment().to_bytes()),
            protocol_configs::protocol_config.eq(miden_node_persistence::encode(protocol_config)),
        ))
        .execute(conn)
        .map_err(Into::into)
}

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
    use diesel::{ExpressionMethods, RunQueryDsl, SqliteConnection};
    use miden_node_utils::fee::test_protocol_config;
    use miden_protocol::Word;
    use miden_protocol::protocol_config::ProtocolConfig;
    use miden_protocol::utils::serde::Serializable;

    use super::{insert_protocol_config, select_protocol_config_by_commitment};
    use crate::db::schema::protocol_configs;
    use crate::errors::DatabaseError;

    fn connection() -> SqliteConnection {
        crate::db::migrations::test_connection()
    }

    #[test]
    fn inserts_and_selects_protocol_config() {
        let mut conn = connection();
        let config = test_protocol_config();
        let commitment = config.to_commitment();

        insert_protocol_config(&mut conn, &config, 0.into()).unwrap();

        assert_eq!(
            select_protocol_config_by_commitment(&mut conn, commitment).unwrap(),
            Some(config)
        );
    }

    #[test]
    fn returns_none_for_unknown_commitment() {
        let mut conn = connection();

        assert_eq!(select_protocol_config_by_commitment(&mut conn, Word::empty()).unwrap(), None);
    }

    #[test]
    fn selects_multiple_protocol_configs_by_commitment() {
        use miden_protocol::asset::AssetId;
        use miden_protocol::testing::account_id::{
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
        };

        let mut conn = connection();
        let first = ProtocolConfig::current(AssetId::new_fungible(
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap(),
        ))
        .unwrap();
        let second = ProtocolConfig::current(AssetId::new_fungible(
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap(),
        ))
        .unwrap();

        insert_protocol_config(&mut conn, &first, 0.into()).unwrap();
        insert_protocol_config(&mut conn, &second, 1.into()).unwrap();

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
        let mut conn = connection();
        let first = test_protocol_config();
        let second = ProtocolConfig::current(miden_protocol::asset::AssetId::new_fungible(
            miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        assert_ne!(first.to_commitment(), second.to_commitment());
        assert_eq!(super::select_protocol_config_commitment_at(&mut conn, 0.into()).unwrap(), None);
        for (height, config) in [(0, &first), (3, &second), (7, &first)] {
            insert_protocol_config(&mut conn, config, height.into()).unwrap();
        }
        for (height, config) in
            [(0, &first), (2, &first), (3, &second), (6, &second), (7, &first), (9, &first)]
        {
            assert_eq!(
                super::select_protocol_config_commitment_at(&mut conn, height.into()).unwrap(),
                Some(config.to_commitment())
            );
        }
        assert_eq!(
            select_protocol_config_by_commitment(&mut conn, first.to_commitment()).unwrap(),
            Some(first.clone())
        );
        assert!(insert_protocol_config(&mut conn, &first, 7.into()).is_err());
        assert!(insert_protocol_config(&mut conn, &second, 7.into()).is_err());
    }

    #[test]
    fn rejects_a_row_stored_under_the_wrong_commitment() {
        let mut conn = connection();
        let config = test_protocol_config();
        let expected = Word::empty();
        let calculated = config.to_commitment();
        diesel::insert_into(protocol_configs::table)
            .values((
                protocol_configs::block_number.eq(0_i64),
                protocol_configs::commitment.eq(expected.to_bytes()),
                protocol_configs::protocol_config.eq(miden_node_persistence::encode(&config)),
            ))
            .execute(&mut conn)
            .unwrap();

        assert!(matches!(
            select_protocol_config_by_commitment(&mut conn, expected),
            Err(DatabaseError::ProtocolConfigCommitmentMismatch {
                expected: actual_expected,
                calculated: actual_calculated,
            }) if actual_expected == expected && actual_calculated == calculated
        ));
    }

    #[test]
    fn rejects_invalid_serialized_protocol_config() {
        let mut conn = connection();
        let commitment = Word::empty();
        diesel::insert_into(protocol_configs::table)
            .values((
                protocol_configs::block_number.eq(0_i64),
                protocol_configs::commitment.eq(commitment.to_bytes()),
                protocol_configs::protocol_config.eq(vec![0xff]),
            ))
            .execute(&mut conn)
            .unwrap();

        assert_eq!(
            super::select_protocol_config_commitment_at(&mut conn, 0.into()).unwrap(),
            Some(commitment)
        );
        assert!(matches!(
            select_protocol_config_by_commitment(&mut conn, commitment),
            Err(DatabaseError::Persistence(_))
        ));
    }

    #[test]
    fn rejects_malformed_protobuf_suffix() {
        let mut conn = connection();
        let config = test_protocol_config();
        let commitment = config.to_commitment();
        let mut bytes = miden_node_persistence::encode(&config);
        bytes.push(0xff);
        diesel::insert_into(protocol_configs::table)
            .values((
                protocol_configs::block_number.eq(0_i64),
                protocol_configs::commitment.eq(commitment.to_bytes()),
                protocol_configs::protocol_config.eq(bytes),
            ))
            .execute(&mut conn)
            .unwrap();

        assert!(matches!(
            select_protocol_config_by_commitment(&mut conn, commitment),
            Err(DatabaseError::Persistence(_))
        ));
    }
}
