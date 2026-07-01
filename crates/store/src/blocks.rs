//! File-based storage for raw block data and block proofs.
//!
//! Block data is stored under `{store_dir}/{epoch:04x}/block_{block_num:08x}.dat`, and proof data
//! for proven blocks is stored under `{store_dir}/{epoch:04x}/proof_{block_num:08x}.dat`.
//!
//! The epoch is derived from the 16 most significant bits of the block number (i.e.,
//! `block_num >> 16`), and both the epoch and block number are formatted as zero-padded
//! hexadecimal strings.

use std::io::ErrorKind;
use std::ops::Not;
use std::path::{Path, PathBuf};

use miden_node_utils::tracing::miden_instrument;
use miden_protocol::block::BlockNumber;
use miden_protocol::utils::serde::Serializable;

use crate::COMPONENT;
use crate::genesis::GenesisBlock;

#[derive(Clone, Debug)]
pub struct BlockStore {
    store_dir: PathBuf,
}

impl BlockStore {
    /// Creates a new [`BlockStore`], creating the directory, inserting the genesis block data
    /// and initializing the proven tip file.
    ///
    /// This _does not_ create any parent directories, so it is expected that the caller has already
    /// created these.
    ///
    /// # Errors
    ///
    /// Uses [`std::fs::create_dir`] and therefore has the same error conditions.
    #[miden_instrument(
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

        // The genesis block is never proven, but is treated as such.
        block_store.save_proven_tip(BlockNumber::GENESIS)?;

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

    #[miden_instrument(
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

    #[miden_instrument(
        target = COMPONENT,
        name = "store.block_store.save_proof",
        skip_all,
        err,
        fields(block.number = block_num.as_u32(), proof_size = data.len())
    )]
    async fn save_proof(&self, block_num: BlockNumber, data: &[u8]) -> std::io::Result<()> {
        let (epoch_path, proof_path) = self.epoch_proof_path(block_num)?;
        if !epoch_path.exists() {
            tokio::fs::create_dir_all(epoch_path).await?;
        }

        tokio::fs::write(proof_path, data).await
    }

    pub async fn load_proof(&self, block_num: BlockNumber) -> std::io::Result<Option<Vec<u8>>> {
        match tokio::fs::read(self.proof_path(block_num)).await {
            Ok(data) => Ok(Some(data)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    // PROVING INPUTS STORAGE
    // --------------------------------------------------------------------------------------------

    #[miden_instrument(
        target = COMPONENT,
        name = "store.block_store.save_proving_inputs",
        skip_all,
        err,
        fields(block.number = block_num.as_u32(), inputs_size = data.len())
    )]
    pub async fn save_proving_inputs(
        &self,
        block_num: BlockNumber,
        data: &[u8],
    ) -> std::io::Result<()> {
        let (epoch_path, inputs_path) = self.epoch_inputs_path(block_num)?;
        if !epoch_path.exists() {
            tokio::fs::create_dir_all(epoch_path).await?;
        }
        tokio::fs::write(inputs_path, data).await
    }

    pub async fn load_proving_inputs(
        &self,
        block_num: BlockNumber,
    ) -> std::io::Result<Option<Vec<u8>>> {
        match tokio::fs::read(self.inputs_path(block_num)).await {
            Ok(data) => Ok(Some(data)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub async fn delete_proving_inputs(&self, block_num: BlockNumber) -> std::io::Result<()> {
        match tokio::fs::remove_file(self.inputs_path(block_num)).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
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

    fn inputs_path(&self, block_num: BlockNumber) -> PathBuf {
        let block_num = block_num.as_u32();
        let epoch = block_num >> 16;
        let epoch_dir = self.store_dir.join(format!("{epoch:04x}"));
        epoch_dir.join(format!("inputs_{block_num:08x}.dat"))
    }

    fn epoch_inputs_path(&self, block_num: BlockNumber) -> std::io::Result<(PathBuf, PathBuf)> {
        let inputs_path = self.inputs_path(block_num);
        let epoch_path = inputs_path.parent().ok_or(std::io::Error::from(ErrorKind::NotFound))?;

        Ok((epoch_path.to_path_buf(), inputs_path))
    }

    // PROVEN TIP STORAGE
    // --------------------------------------------------------------------------------------------

    /// Saves the proof, advances the proven tip, and deletes the proving inputs.
    ///
    /// Must be called in strictly ascending [`BlockNumber`] order: the proven tip file records
    /// the highest consecutive proven block, so committing out of order would leave a gap.
    pub async fn commit_proof(&self, block_num: BlockNumber, proof: &[u8]) -> std::io::Result<()> {
        self.save_proof(block_num, proof).await?;
        self.save_proven_tip(block_num)?;
        self.delete_proving_inputs(block_num).await
    }

    /// Reads the proven tip from disk and returns it.
    pub fn load_proven_tip(&self) -> std::io::Result<BlockNumber> {
        Self::read_proven_tip_from(&self.proven_tip_path())
    }

    /// Atomically writes `tip` to the proven tip file (write to temp, then rename).
    fn save_proven_tip(&self, tip: BlockNumber) -> std::io::Result<()> {
        let path = self.proven_tip_path();
        let tmp = path.with_extension("tmp");
        fs_err::write(&tmp, tip.as_u32().to_le_bytes())?;
        fs_err::rename(&tmp, &path)
    }

    fn proven_tip_path(&self) -> PathBuf {
        self.store_dir.join("proven_tip")
    }

    fn read_proven_tip_from(path: &Path) -> std::io::Result<BlockNumber> {
        let bytes = fs_err::read(path)?;
        let arr: [u8; 4] = bytes.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "proven tip file has unexpected size (expected 4 bytes)",
            )
        })?;
        Ok(BlockNumber::from(u32::from_le_bytes(arr)))
    }

    pub fn display(&self) -> std::path::Display<'_> {
        self.store_dir.display()
    }
}
