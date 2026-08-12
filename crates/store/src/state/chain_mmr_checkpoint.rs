//! On-disk checkpoint of the chain MMR.
//!
//! The blockchain MMR is derived entirely from the block header commitments in SQLite, but
//! rebuilding it hashes one merge per block, so the cost of a rebuild grows with chain height.
//! The checkpoint caches the derived structure in a flat file: startup restores it with a single
//! sequential read and only appends the blocks committed since the checkpoint was taken.
//!
//! The checkpoint is a pure cache. Because the MMR is append-only, a stale checkpoint is a valid
//! prefix of the current chain and is simply topped up; a corrupt or divergent checkpoint is
//! discarded in favour of a full rebuild, guarded by the chain-commitment consistency check in
//! the loader. Deleting the file is always safe.

use std::path::{Path, PathBuf};

use miden_protocol::block::Blockchain;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_node_tracing::warn;

use crate::LOG_TARGET;

/// File name of the chain MMR checkpoint within the data directory.
pub(crate) const CHAIN_MMR_CHECKPOINT_FILENAME: &str = "chainmmr.bin";

/// Handle to the chain MMR checkpoint file within the data directory.
///
/// Reads and writes are best-effort: any failure is logged and treated as "no checkpoint", never
/// surfaced as an error, since the database remains the source of truth.
#[derive(Debug, Clone)]
pub(crate) struct ChainMmrCheckpoint {
    path: PathBuf,
}

impl ChainMmrCheckpoint {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join(CHAIN_MMR_CHECKPOINT_FILENAME),
        }
    }

    /// Reads the checkpoint, returning `None` if it is missing, unreadable, or contains more blocks
    /// than `chain_length` (e.g. the database was restored from an older backup, so the checkpoint
    /// is not a prefix and cannot be topped up).
    pub fn read(&self, chain_length: u32) -> Option<Blockchain> {
        let bytes = match fs_err::read(&self.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
            Err(err) => {
                warn!(target: LOG_TARGET, %err, "Failed to read the chain MMR checkpoint; rebuilding from the database");
                return None;
            },
        };

        let blockchain = match Blockchain::read_from_bytes(&bytes) {
            Ok(blockchain) => blockchain,
            Err(err) => {
                warn!(target: LOG_TARGET, %err, "Failed to decode the chain MMR checkpoint; rebuilding from the database");
                return None;
            },
        };

        if blockchain.num_blocks() > chain_length {
            warn!(
                target: LOG_TARGET,
                checkpoint_blocks = blockchain.num_blocks(),
                chain_length,
                "Chain MMR checkpoint is ahead of the database; rebuilding from the database"
            );
            return None;
        }

        Some(blockchain)
    }

    /// Atomically replaces the checkpoint with the given blockchain.
    pub fn write(&self, blockchain: &Blockchain) {
        let mut bytes = Vec::with_capacity(blockchain.as_mmr().forest().num_nodes() * 32);
        blockchain.write_into(&mut bytes);

        let tmp_path = self.path.with_extension("tmp");
        let result =
            fs_err::write(&tmp_path, &bytes).and_then(|()| fs_err::rename(&tmp_path, &self.path));
        if let Err(err) = result {
            warn!(target: LOG_TARGET, %err, "Failed to write the chain MMR checkpoint");
        }
    }
}

#[cfg(test)]
mod tests {
    use miden_crypto::merkle::mmr::Mmr;
    use miden_protocol::Word;

    use super::*;

    fn chain(blocks: u32) -> Blockchain {
        let mmr = Mmr::try_from_iter((0..blocks).map(|i| Word::from([i, 0, 0, 0u32])))
            .expect("test MMR should build");
        Blockchain::from_mmr_unchecked(mmr)
    }

    #[test]
    fn read_returns_none_when_missing() {
        let dir = tempfile::tempdir().expect("temp directory should be created");
        assert!(ChainMmrCheckpoint::new(dir.path()).read(5).is_none());
    }

    #[test]
    fn write_read_round_trips() {
        let dir = tempfile::tempdir().expect("temp directory should be created");
        let checkpoint = ChainMmrCheckpoint::new(dir.path());
        let blockchain = chain(5);

        checkpoint.write(&blockchain);

        let restored = checkpoint.read(5).expect("checkpoint should round-trip");
        assert_eq!(restored.num_blocks(), 5);
        assert_eq!(restored.commitment(), blockchain.commitment());
    }

    #[test]
    fn read_discards_checkpoint_ahead_of_database() {
        let dir = tempfile::tempdir().expect("temp directory should be created");
        let checkpoint = ChainMmrCheckpoint::new(dir.path());
        checkpoint.write(&chain(5));

        // A checkpoint with more blocks than the database is not a prefix and must be discarded; a
        // checkpoint at or behind the chain length is usable.
        assert!(checkpoint.read(3).is_none());
        assert!(checkpoint.read(5).is_some());
        assert!(checkpoint.read(10).is_some());
    }
}
