use std::io::ErrorKind;
use std::ops::Not;
use std::path::PathBuf;

use miden_protocol::block::BlockNumber;
use miden_protocol::utils::serde::Serializable;
use tracing::instrument;

use crate::COMPONENT;
use crate::genesis::GenesisBlock;

#[derive(Debug)]
pub struct BlockStore {
    store_dir: PathBuf,
}

impl BlockStore {
    /// Creates a new [`BlockStore`], creating the directory and inserting the genesis block data.
    ///
    /// This _does not_ create any parent directories, so it is expected that the caller has already
    /// created these.
    ///
    /// # Errors
    ///
    /// Uses [`std::fs::create_dir`] and therefore has the same error conditions.
    #[instrument(
        target = COMPONENT,
        name = "store.block_store.bootstrap",
        skip_all,
        err,
        fields(path = %store_dir.display()),
    )]
    pub fn bootstrap(store_dir: PathBuf, genesis_block: &GenesisBlock) -> std::io::Result<Self> {
        fs_err::create_dir(&store_dir)?;

        let block_store = Self { store_dir };
        block_store.save_block_blocking(BlockNumber::GENESIS, &genesis_block.inner().to_bytes())?;

        Ok(block_store)
    }

    /// Loads an existing [`BlockStore`].
    ///
    /// A new [`BlockStore`] can be created using [`BlockStore::bootstrap`].
    ///
    /// A best effort is made to ensure the directory exists and is accessible, but will still run
    /// afoul of TOCTOU issues as these are impossible to rule out.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///   - the directory does not exist, or
    ///   - the directory is not accessible, or
    ///   - it is not a directory
    ///
    /// See also: [`std::fs::metadata`].
    pub fn load(store_dir: PathBuf) -> std::io::Result<Self> {
        let meta = fs_err::metadata(&store_dir)?;
        if meta.is_dir().not() {
            return Err(ErrorKind::NotADirectory.into());
        }

        Ok(Self { store_dir })
    }

    pub async fn load_block(&self, block_num: BlockNumber) -> std::io::Result<Option<Vec<u8>>> {
        match tokio::fs::read(self.block_path(block_num)).await {
            Ok(data) => Ok(Some(data)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    #[instrument(
        target = COMPONENT,
        name = "store.block_store.save_block",
        skip(self, data),
        err,
        fields(block_size = data.len())
    )]
    pub async fn save_block(&self, block_num: BlockNumber, data: &[u8]) -> std::io::Result<()> {
        let (epoch_path, block_path) = self.epoch_block_path(block_num)?;
        if !epoch_path.exists() {
            tokio::fs::create_dir_all(epoch_path).await?;
        }

        tokio::fs::write(block_path, data).await
    }

    pub fn save_block_blocking(&self, block_num: BlockNumber, data: &[u8]) -> std::io::Result<()> {
        let (epoch_path, block_path) = self.epoch_block_path(block_num)?;
        if !epoch_path.exists() {
            fs_err::create_dir_all(epoch_path)?;
        }

        fs_err::write(block_path, data)
    }

    // PROOF STORAGE
    // --------------------------------------------------------------------------------------------

    #[instrument(
        target = COMPONENT,
        name = "store.block_store.save_proof",
        skip(self, data),
        err,
        fields(proof_size = data.len())
    )]
    pub async fn save_proof(&self, block_num: BlockNumber, data: &[u8]) -> std::io::Result<()> {
        let (epoch_path, proof_path) = self.epoch_proof_path(block_num)?;
        if !epoch_path.exists() {
            tokio::fs::create_dir_all(epoch_path).await?;
        }

        tokio::fs::write(proof_path, data).await
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    fn block_path(&self, block_num: BlockNumber) -> PathBuf {
        let block_num = block_num.as_u32();
        let epoch = block_num >> 16;
        let epoch_dir = self.store_dir.join(format!("{epoch:04x}"));
        epoch_dir.join(format!("block_{block_num:08x}.dat"))
    }

    fn proof_path(&self, block_num: BlockNumber) -> PathBuf {
        let block_num = block_num.as_u32();
        let epoch = block_num >> 16;
        let epoch_dir = self.store_dir.join(format!("{epoch:04x}"));
        epoch_dir.join(format!("proof_{block_num:08x}.dat"))
    }

    fn epoch_block_path(&self, block_num: BlockNumber) -> std::io::Result<(PathBuf, PathBuf)> {
        let block_path = self.block_path(block_num);
        let epoch_path = block_path.parent().ok_or(std::io::Error::from(ErrorKind::NotFound))?;

        Ok((epoch_path.to_path_buf(), block_path))
    }

    fn epoch_proof_path(&self, block_num: BlockNumber) -> std::io::Result<(PathBuf, PathBuf)> {
        let proof_path = self.proof_path(block_num);
        let epoch_path = proof_path.parent().ok_or(std::io::Error::from(ErrorKind::NotFound))?;

        Ok((epoch_path.to_path_buf(), proof_path))
    }

    pub fn display(&self) -> std::path::Display<'_> {
        self.store_dir.display()
    }
}
