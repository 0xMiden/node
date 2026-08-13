//! On-disk checkpoint of the chain MMR.
//!
//! The blockchain MMR is derived entirely from the block header commitments in SQLite, but
//! rebuilding it hashes one merge per block, so the cost of a rebuild grows with chain height.
//! The checkpoint caches the derived structure in a flat file: startup restores it with a single
//! sequential read and only appends the blocks committed since the checkpoint was taken.
//!
//! The file is the MMR's node array stored verbatim: a concatenation of 32-byte nodes with no
//! header or framing. The MMR is append-only, so refreshing the checkpoint appends just the nodes
//! added since the previous refresh, and any prefix of the file covering a whole number of blocks
//! is itself a valid checkpoint of the corresponding chain prefix. Appends are buffered and never
//! synced: a crash may tear or lose the tail, which the read path drops before restoring the
//! remaining prefix.
//!
//! The checkpoint is a pure cache. A stale checkpoint is simply topped up by the loader; a corrupt
//! or divergent checkpoint is discarded in favour of a full rebuild, guarded by the
//! chain-commitment consistency check in the loader. Deleting the file is always safe.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use miden_crypto::merkle::mmr::Mmr;
use miden_node_utils::ErrorReport;
use miden_protocol::Word;
use miden_protocol::block::Blockchain;
use miden_protocol::utils::serde::{ByteWriter, Deserializable, Serializable};
use tracing::warn;

use crate::LOG_TARGET;

/// File name of the chain MMR checkpoint within the data directory.
pub(crate) const CHAIN_MMR_CHECKPOINT_FILENAME: &str = "chainmmr.bin";

/// Serialized size of one MMR node.
const NODE_SIZE: usize = Word::SERIALIZED_SIZE;

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

    /// Reads the checkpoint, restoring the longest usable prefix of the file: a torn tail from an
    /// interrupted append is dropped, and a checkpoint with more blocks than `chain_length` (e.g.
    /// the database was restored from an older backup) is cut back to the database's chain length.
    /// Returns `None` if the file is missing, unreadable, undecodable, or holds no complete block.
    pub fn read(&self, chain_length: u32) -> Option<Blockchain> {
        let bytes = fs_err::read(&self.path)
            .inspect_err(|err|
                if err.kind() != std::io::ErrorKind::NotFound {
                    warn!(target: LOG_TARGET, err = %err.as_report(), "Failed to read the chain MMR checkpoint; rebuilding from the database");
                }
            )
            .ok()?;

        let num_blocks = largest_chain_prefix(bytes.len() / NODE_SIZE, chain_length);
        if num_blocks == 0 {
            return None;
        }
        let num_nodes = num_nodes_in_chain(num_blocks);
        // Restoring the valid prefix needs no dedicated logic: the decode below always takes
        // exactly `num_nodes` nodes, which in the healthy case is the whole file. This branch only
        // reports when tail bytes are actually being dropped.
        if num_nodes * NODE_SIZE != bytes.len() {
            warn!(
                target: LOG_TARGET,
                file_bytes = bytes.len(),
                restored_blocks = num_blocks,
                chain_length,
                "Chain MMR checkpoint tail is unusable (torn append or ahead of the database); restoring the valid prefix"
            );
        }

        // The node array is an in-memory struct at this point; what is missing is a constructor
        // that turns raw nodes into an `Mmr` without re-hashing them (`nodes` is private, and
        // `Mmr::try_from_iter` re-hashes every merge). The only non-hashing path in is the
        // `Deserializable` impl, so the node bytes are prefixed with the two integers its layout
        // expects — the forest's leaf count and the node-array length — and decoded.
        //
        // TODO: Replace with `Mmr::from_nodes_unchecked` (decode the node bytes into `Word`s and
        // construct directly) once the node is on a miden-vm release containing
        // 0xMiden/miden-vm#3585, removing the extra copy. The layout coupling is safe meanwhile:
        // upstream documents the flat `forest || nodes` encoding as the stable wire format.
        let mut serialized = Vec::with_capacity(2 * size_of::<u64>() + num_nodes * NODE_SIZE);
        serialized.write_usize(num_blocks as usize);
        serialized.write_usize(num_nodes);
        serialized.extend_from_slice(&bytes[..num_nodes * NODE_SIZE]);

        match Mmr::read_from_bytes(&serialized) {
            Ok(mmr) => Some(Blockchain::from_mmr_unchecked(mmr)),
            Err(err) => {
                warn!(target: LOG_TARGET, err = %err.as_report(), "Failed to decode the chain MMR checkpoint; rebuilding from the database");
                None
            },
        }
    }

    /// Atomically replaces the checkpoint with the given blockchain.
    ///
    /// The replacement is atomic against concurrent readers (write to a temporary file, then
    /// rename), but like [`Self::append`] it is never fsynced: a crash may lose the replacement,
    /// which only costs the next startup a rebuild or a longer top-up.
    pub fn write(&self, blockchain: &Blockchain) {
        let bytes = node_bytes_from(blockchain, 0);

        let tmp_path = self.path.with_extension("tmp");
        let result =
            fs_err::write(&tmp_path, &bytes).and_then(|()| fs_err::rename(&tmp_path, &self.path));
        if let Err(err) = result {
            warn!(target: LOG_TARGET, err = %err.as_report(), "Failed to write the chain MMR checkpoint");
        }
    }

    /// Appends the nodes added after the first `from_blocks` blocks to the checkpoint file,
    /// returning whether the file ends at `blockchain`'s tip as a result.
    ///
    /// The write goes to the OS page cache and is never fsynced: the checkpoint is a pure cache,
    /// so durability is not required, and skipping the sync keeps the append cheap enough to run
    /// inline on the block-apply path. A crash may lose or tear the unsynced tail; [`Self::read`]
    /// drops it and the loader tops the difference up from the database.
    ///
    /// The append is only valid if the file ends exactly where the new nodes begin; when it does
    /// not (a torn earlier append, an ahead-of-database file that `read` cut back, or a failed
    /// earlier write), the file is left untouched and `false` is returned. Healing — rewriting
    /// the checkpoint via [`Self::write`] — is deliberately left to callers off the block-apply
    /// path, since the full rewrite's I/O grows with chain height.
    pub fn append(&self, blockchain: &Blockchain, from_blocks: u32) -> bool {
        debug_assert!(from_blocks <= blockchain.num_blocks());

        let expected_len = (num_nodes_in_chain(from_blocks) * NODE_SIZE) as u64;
        let file_len = match fs_err::metadata(&self.path) {
            Ok(metadata) => metadata.len(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0,
            Err(err) => {
                warn!(target: LOG_TARGET, err = %err.as_report(), "Failed to stat the chain MMR checkpoint; skipping the append");
                return false;
            },
        };
        if file_len != expected_len {
            warn!(
                target: LOG_TARGET,
                file_len,
                expected_len,
                "Chain MMR checkpoint does not end at the expected node; skipping the append"
            );
            return false;
        }
        if from_blocks == blockchain.num_blocks() {
            return true;
        }

        let bytes = node_bytes_from(blockchain, from_blocks);
        let result = fs_err::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)
            .and_then(|mut file| file.write_all(&bytes));
        match result {
            Ok(()) => true,
            Err(err) => {
                warn!(target: LOG_TARGET, err = %err.as_report(), "Failed to append to the chain MMR checkpoint");
                false
            },
        }
    }
}

/// Number of nodes in the MMR of a chain with `num_blocks` blocks: each block adds its own leaf
/// node plus one parent node per binary-tree merge, totalling `2 * blocks - popcount(blocks)`.
fn num_nodes_in_chain(num_blocks: u32) -> usize {
    2 * num_blocks as usize - num_blocks.count_ones() as usize
}

/// Returns the largest block count whose MMR node array fits within `num_nodes` complete nodes,
/// capped at `chain_length`.
///
/// Node counts don't map 1:1 to block counts (see [`num_nodes_in_chain`]): a file cut short by a
/// torn append usually ends between block boundaries, and only the nodes up to the last whole
/// block are usable. This binary-searches for the largest block count whose complete node array
/// is present, capped at the database's `chain_length` for the case where the checkpoint is
/// ahead of the database (e.g. the database was restored from an older backup).
/// [`ChainMmrCheckpoint::read`] then decodes just that prefix of the file and ignores the rest.
fn largest_chain_prefix(num_nodes: usize, chain_length: u32) -> u32 {
    // `num_nodes_in_chain` is strictly increasing, so "fits in the file" is a monotone predicate
    // and the largest block count satisfying it is found by binary search. `lo` always satisfies
    // the predicate; `hi` starts at the answer's cheap upper bounds (`chain_length`, and
    // `num_nodes` since every block contributes at least one node).
    let mut lo = 0u64;
    let mut hi = u64::from(chain_length).min(num_nodes as u64);
    while lo < hi {
        // Round the probe up: with rounding down, `hi == lo + 1` would probe `lo` and loop forever.
        // The u64 arithmetic avoids overflow near `u32::MAX`.
        let mid = lo + (hi - lo).div_ceil(2);
        if num_nodes_in_chain(mid as u32) <= num_nodes {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo as u32
}

/// Serializes the MMR nodes appended after the first `from_blocks` blocks.
///
/// TODO: Serialize just the new nodes via `Mmr::nodes_from(start)` once the node is on a
/// miden-vm release containing 0xMiden/miden-vm#3585. Until then the whole MMR is serialized —
/// its layout ends with the node array — and the new nodes' bytes are taken from the tail.
fn node_bytes_from(blockchain: &Blockchain, from_blocks: u32) -> Vec<u8> {
    let mmr = blockchain.as_mmr();
    let serialized = mmr.to_bytes();
    let new_bytes = (mmr.forest().num_nodes() - num_nodes_in_chain(from_blocks)) * NODE_SIZE;
    serialized[serialized.len() - new_bytes..].to_vec()
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
    fn read_truncates_checkpoint_ahead_of_database() {
        let dir = tempfile::tempdir().expect("temp directory should be created");
        let checkpoint = ChainMmrCheckpoint::new(dir.path());
        checkpoint.write(&chain(5));

        // A checkpoint with more blocks than the database is cut back to the database's chain
        // length; at or behind the chain length it is restored whole.
        let truncated = checkpoint.read(3).expect("prefix should be restored");
        assert_eq!(truncated.num_blocks(), 3);
        assert_eq!(truncated.commitment(), chain(3).commitment());

        let whole = checkpoint.read(10).expect("whole checkpoint should be restored");
        assert_eq!(whole.num_blocks(), 5);
    }

    #[test]
    fn append_extends_existing_checkpoint() {
        let dir = tempfile::tempdir().expect("temp directory should be created");
        let checkpoint = ChainMmrCheckpoint::new(dir.path());
        checkpoint.write(&chain(3));

        assert!(checkpoint.append(&chain(8), 3));

        let restored = checkpoint.read(8).expect("appended checkpoint should be restored");
        assert_eq!(restored.num_blocks(), 8);
        assert_eq!(restored.commitment(), chain(8).commitment());
    }

    #[test]
    fn append_creates_missing_checkpoint() {
        let dir = tempfile::tempdir().expect("temp directory should be created");
        let checkpoint = ChainMmrCheckpoint::new(dir.path());

        assert!(checkpoint.append(&chain(4), 0));

        let restored = checkpoint.read(4).expect("created checkpoint should be restored");
        assert_eq!(restored.num_blocks(), 4);
        assert_eq!(restored.commitment(), chain(4).commitment());
    }

    #[test]
    fn append_skips_on_length_mismatch() {
        let dir = tempfile::tempdir().expect("temp directory should be created");
        let checkpoint = ChainMmrCheckpoint::new(dir.path());
        checkpoint.write(&chain(5));

        // The file holds 5 blocks but the append expects it to end at 3; the file is left untouched
        // — healing by full rewrite is the caller's call, off the block-apply path.
        assert!(!checkpoint.append(&chain(8), 3));

        let restored = checkpoint.read(8).expect("untouched checkpoint should be restored");
        assert_eq!(restored.num_blocks(), 5);
        assert_eq!(restored.commitment(), chain(5).commitment());
    }

    #[test]
    fn read_drops_torn_tail() {
        let dir = tempfile::tempdir().expect("temp directory should be created");
        let checkpoint = ChainMmrCheckpoint::new(dir.path());
        let blockchain = chain(5);
        checkpoint.write(&blockchain);

        // A crash mid-append leaves trailing bytes that don't form complete blocks: a partial node,
        // and a whole node that doesn't complete a block on its own.
        for torn_tail in [&[0u8; 10][..], &[0u8; NODE_SIZE][..]] {
            let mut file = fs_err::OpenOptions::new()
                .append(true)
                .open(dir.path().join(CHAIN_MMR_CHECKPOINT_FILENAME))
                .expect("checkpoint file should open for appending");
            file.write_all(torn_tail).expect("torn tail should be written");
            drop(file);

            let restored = checkpoint.read(10).expect("valid prefix should be restored");
            assert_eq!(restored.num_blocks(), 5);
            assert_eq!(restored.commitment(), blockchain.commitment());

            checkpoint.write(&blockchain);
        }
    }

    #[test]
    fn largest_chain_prefix_finds_last_whole_block() {
        // Every node count between two block boundaries maps back to the lower boundary.
        for blocks in 0..=64u32 {
            let boundary = num_nodes_in_chain(blocks);
            let next_boundary = num_nodes_in_chain(blocks + 1);
            for num_nodes in boundary..next_boundary {
                assert_eq!(largest_chain_prefix(num_nodes, u32::MAX), blocks);
            }
        }
    }

    #[test]
    fn largest_chain_prefix_caps_at_chain_length() {
        // A checkpoint ahead of the database (e.g. restored from an older backup) is cut back.
        assert_eq!(largest_chain_prefix(num_nodes_in_chain(64), 10), 10);
        assert_eq!(largest_chain_prefix(num_nodes_in_chain(64), 0), 0);
        // The u64 midpoint arithmetic holds up at the u32 extreme.
        assert_eq!(largest_chain_prefix(num_nodes_in_chain(u32::MAX), u32::MAX), u32::MAX);
    }

    #[test]
    fn read_rejects_undecodable_nodes() {
        let dir = tempfile::tempdir().expect("temp directory should be created");
        let checkpoint = ChainMmrCheckpoint::new(dir.path());

        // 0xFF bytes are not canonical field elements, so decoding fails.
        fs_err::write(dir.path().join(CHAIN_MMR_CHECKPOINT_FILENAME), [0xFF; NODE_SIZE])
            .expect("corrupt checkpoint should be written");

        assert!(checkpoint.read(5).is_none());
    }
}
