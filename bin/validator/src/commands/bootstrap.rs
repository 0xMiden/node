use std::num::NonZeroUsize;
use std::path::Path;

use anyhow::Context;
use miden_node_store::BlockStore;
use miden_node_tracing::info;
use miden_node_utils::fs::ensure_empty_directory;
use miden_node_utils::genesis::read_genesis_block;
use miden_validator::DataDirectory;

/// Runs the `bootstrap` command: seeds this validator's database from the genesis block file
/// produced by the `genesis` command.
///
/// The genesis block is the chain's trust root and carries no signatures; it must come from a
/// trusted source. This command verifies the block and its protocol configuration. It persists
/// the block as the chain tip.
pub async fn bootstrap(
    data_directory: &Path,
    sqlite_connection_pool_size: NonZeroUsize,
    genesis_block_file: &Path,
) -> anyhow::Result<()> {
    info!(
        target: miden_validator::LOG_TARGET,
        "Bootstrapping validator",
        service.name = "miden-validator",
        service.version = env!("CARGO_PKG_VERSION"),
        genesis.file = genesis_block_file,
        data.directory = data_directory
    );

    ensure_empty_directory(data_directory)?;
    let dirs = DataDirectory::load(data_directory.to_path_buf())
        .context("failed to load the data directory")?;

    let genesis_block =
        read_genesis_block(genesis_block_file).context("failed to read genesis block file")?;
    let genesis_commitment = genesis_block.inner().header().commitment();

    let _ = BlockStore::bootstrap(dirs.block_store_dir(), &genesis_block)?;

    let (genesis_block, protocol_config) = genesis_block.into_parts();
    let (genesis_header, ..) = genesis_block.into_parts();
    miden_validator::db::bootstrap(
        dirs.database_path(),
        sqlite_connection_pool_size,
        genesis_header,
        protocol_config,
    )
    .await
    .context("failed to bootstrap the validator database")?;

    info!(
        target: miden_validator::LOG_TARGET,
        "Validator bootstrap complete",
        genesis.commitment = genesis_commitment,
        data.directory = data_directory
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use miden_protocol::block::BlockNumber;
    use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
    use miden_protocol::utils::serde::{Deserializable, Serializable};

    use super::*;

    #[tokio::test]
    async fn bootstrap_writes_all_outputs_before_returning_success() {
        let root = tempfile::tempdir().unwrap();
        let genesis_directory = root.path().join("genesis");
        let accounts_directory = root.path().join("accounts");
        let data_directory = root.path().join("data");

        let validator_key = SigningKey::read_from_bytes(&[7; 32])
            .expect("test signing key should decode")
            .public_key();
        super::super::genesis::generate(
            &genesis_directory,
            &accounts_directory,
            None,
            vec![validator_key],
        )
        .expect("genesis should complete");

        bootstrap(
            &data_directory,
            NonZeroUsize::new(2).unwrap(),
            &genesis_directory.join("genesis.dat"),
        )
        .await
        .expect("bootstrap should complete");

        assert!(genesis_directory.join("genesis.dat").is_file());
        assert!(data_directory.join("validator.sqlite3").is_file());

        let genesis = read_genesis_block(&genesis_directory.join("genesis.dat")).unwrap();
        let config = genesis.protocol_config().clone();
        let commitment = genesis.inner().header().protocol_config_commitment();
        let validator_db = miden_validator::db::load(data_directory.join("validator.sqlite3"))
            .await
            .unwrap();
        assert_eq!(
            validator_db.load_protocol_config(commitment).await.unwrap(),
            Some(config.clone())
        );
        let block_bytes = genesis.inner().to_bytes();
        assert_eq!(config.to_commitment(), commitment);
        let node_directory = root.path().join("node");
        fs_err::create_dir(&node_directory).unwrap();
        miden_node_store::State::bootstrap(genesis, &node_directory).unwrap();
        let directories = miden_node_store::DataDirectory::load(node_directory).unwrap();
        let block_store = BlockStore::load(directories.block_store_dir()).unwrap();
        assert_eq!(block_store.load_block(BlockNumber::GENESIS).await.unwrap(), Some(block_bytes));
        let db = miden_node_store::Db::load(directories.database_path()).await.unwrap();
        assert_eq!(
            db.select_protocol_config_by_commitment(commitment).await.unwrap(),
            Some(config)
        );

        assert!(
            fs_err::read_dir(&accounts_directory)
                .expect("accounts directory should be readable")
                .next()
                .is_some(),
            "genesis should write generated account files",
        );
        assert!(
            accounts_directory.join("native_faucet.mac").is_file(),
            "genesis should write the generated native faucet account file",
        );
    }

    #[tokio::test]
    async fn bootstrap_rejects_block_only_genesis_before_creating_database() {
        use miden_node_store::genesis::GenesisState;
        use miden_node_utils::fee::{test_fee_params, test_protocol_config};
        use miden_protocol::block::ValidatorConfig;

        let root = tempfile::tempdir().unwrap();
        let key = SigningKey::read_from_bytes(&[7; 32]).unwrap().public_key();
        let genesis = GenesisState::new(
            Vec::new(),
            test_fee_params(),
            0,
            ValidatorConfig::new(vec![key], 1).unwrap(),
            test_protocol_config(),
        )
        .into_block()
        .unwrap();
        let path = root.path().join("genesis.dat");
        fs_err::write(&path, genesis.inner().to_bytes()).unwrap();
        let data_directory = root.path().join("data");
        assert!(bootstrap(&data_directory, NonZeroUsize::new(2).unwrap(), &path).await.is_err());
        assert!(!data_directory.join("validator.sqlite3").exists());
    }
}
