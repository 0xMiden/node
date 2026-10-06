//! Returns the commitment of the protocol configuration active at a block.

use miden_node_db::sqlite::ReadTx;
use miden_protocol::Word;
use miden_protocol::block::BlockNumber;

use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_protocol_config_commitment_at.sql");

/// Returns the commitment of the configuration active at `block_number`.
///
/// The active configuration is the one with the latest activation at or before `block_number`.
/// Returns `None` if no configuration activates at or before `block_number`.
pub(crate) fn select_protocol_config_commitment_at(
    tx: &ReadTx<'_>,
    block_number: BlockNumber,
) -> Result<Option<Word>, DatabaseError> {
    Ok(tx.query(SQL, &[&block_number], |row| row.get::<Word>(0))?.into_iter().next())
}

#[cfg(test)]
mod tests {
    use miden_node_utils::fee::test_protocol_config;
    use miden_protocol::Word;
    use miden_protocol::asset::AssetId;
    use miden_protocol::block::BlockNumber;
    use miden_protocol::protocol_config::ProtocolConfig;
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1;

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

    fn select_protocol_config_commitment_at(
        db: &TestDb,
        block_number: BlockNumber,
    ) -> Result<Option<Word>, DatabaseError> {
        db.read(move |tx| queries::select_protocol_config_commitment_at(tx, block_number))
    }

    fn select_protocol_config_by_commitment(
        db: &TestDb,
        commitment: Word,
    ) -> Result<Option<ProtocolConfig>, DatabaseError> {
        db.read(move |tx| queries::select_protocol_config_by_commitment(tx, commitment))
    }

    #[test]
    fn selects_commitment_at_activation_boundaries() {
        let db = TestDb::new();
        let first = test_protocol_config();
        let second = ProtocolConfig::current(AssetId::new_fungible(
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap(),
        ))
        .unwrap();
        assert_ne!(first.to_commitment(), second.to_commitment());
        assert_eq!(select_protocol_config_commitment_at(&db, 0.into()).unwrap(), None);
        for (height, config) in [(0, &first), (3, &second), (7, &first)] {
            insert_protocol_config(&db, config, height.into()).unwrap();
        }
        for (height, config) in
            [(0, &first), (2, &first), (3, &second), (6, &second), (7, &first), (9, &first)]
        {
            assert_eq!(
                select_protocol_config_commitment_at(&db, height.into()).unwrap(),
                Some(config.to_commitment())
            );
        }
        assert_eq!(
            select_protocol_config_by_commitment(&db, first.to_commitment()).unwrap(),
            Some(first.clone())
        );
        assert!(insert_protocol_config(&db, &first, 7.into()).is_err());
        assert!(insert_protocol_config(&db, &second, 7.into()).is_err());
    }
}
