//! Funding service database initialization and migration.

use std::path::Path;

use anyhow::{Context, ensure};
use miden_node_utils::fs::ensure_empty_directory;
use miden_node_utils::genesis::GenesisBlock;
use miden_protocol::account::{AccountId, AccountType};

use crate::db::{DatabaseIdentity, FundingDatabase};

/// The database filename within the funding service's data directory.
pub const DATABASE_FILENAME: &str = "funding.sqlite3";

/// Creates a database bound to a trusted genesis block and the operator's funding account.
///
/// The funding account must be public. The data directory must be absent or empty; an existing
/// database is never replaced.
pub async fn bootstrap(
    data_directory: &Path,
    account_id: AccountId,
    genesis: &GenesisBlock,
) -> anyhow::Result<()> {
    let fee_asset_id = genesis.protocol_config().fee_asset_id();
    ensure!(
        account_id.account_type() == AccountType::Public,
        "the funding account must be public"
    );
    ensure_empty_directory(data_directory)?;
    FundingDatabase::bootstrap(
        &data_directory.join(DATABASE_FILENAME),
        DatabaseIdentity {
            genesis_commitment: genesis.inner().header().commitment(),
            funding_account_id: account_id,
            fee_asset_id,
        },
    )
    .await
    .context("failed to bootstrap the funding database")?;
    Ok(())
}

/// Applies pending migrations to an existing funding database while the service is stopped.
pub fn migrate(data_directory: &Path) -> anyhow::Result<()> {
    FundingDatabase::migrate(&data_directory.join(DATABASE_FILENAME))
        .context("failed to apply funding database migrations")
}

#[cfg(test)]
mod tests {
    use miden_protocol::block::{BlockSignatures, SignedBlock};

    use super::*;
    use crate::FundingServiceConfig;
    use crate::test_utils::Fixture;

    #[tokio::test]
    async fn bootstrap_binds_the_account_and_genesis_and_migrates_offline() {
        let fixture = Fixture::new(1_000, 0).unwrap();
        let chain = fixture.chain.lock().await;
        let (header, body, ..) = chain.latest_block().into_parts();
        let genesis = GenesisBlock::new(
            SignedBlock::new(header, body, BlockSignatures::new(Vec::new()).unwrap()).unwrap(),
            chain.protocol_config().clone(),
        )
        .unwrap();
        let identity = DatabaseIdentity {
            genesis_commitment: genesis.inner().header().commitment(),
            funding_account_id: fixture.funder.id(),
            fee_asset_id: genesis.protocol_config().fee_asset_id(),
        };
        drop(chain);
        let dir = tempfile::tempdir().unwrap();
        let data_directory = dir.path().join("data");

        bootstrap(&data_directory, identity.funding_account_id, &genesis).await.unwrap();
        migrate(&data_directory).unwrap();
        let database = FundingDatabase::open_and_verify(
            &data_directory.join(DATABASE_FILENAME),
            identity.genesis_commitment,
            identity.fee_asset_id,
        )
        .await
        .unwrap();
        assert_eq!(database.identity(), identity);
        assert!(
            database
                .pending_requests(std::num::NonZeroUsize::new(1).unwrap())
                .await
                .unwrap()
                .is_empty()
        );
        drop(database);

        assert!(bootstrap(&data_directory, identity.funding_account_id, &genesis).await.is_err());
        FundingDatabase::open_and_verify(
            &data_directory.join(DATABASE_FILENAME),
            identity.genesis_commitment,
            identity.fee_asset_id,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn start_requires_bootstrap_before_connecting_to_the_node() {
        let dir = tempfile::tempdir().unwrap();
        let result = FundingServiceConfig::new(
            "http://127.0.0.1:1".parse().unwrap(),
            dir.path().join("funding.secret"),
            Vec::new(),
            dir.path().join("missing"),
        )
        .build()
        .await;
        let error = result.err().expect("an uninitialized service must not start");
        assert!(error.to_string().contains("run bootstrap"), "{error:#}");
        assert!(!dir.path().join("missing").exists());
    }
}
