use std::path::{Path, PathBuf};

use miden_protocol::block::BlockNumber;
use tokio::sync::watch;

/// Cloneable handle that can advance the proven chain tip.
///
/// All clones share the same underlying watch channel, so any `advance()` call is immediately
/// visible to all receivers returned by `subscribe()`.
#[derive(Clone)]
pub struct ProvenTipWriter(watch::Sender<BlockNumber>);

impl ProvenTipWriter {
    /// Creates a new writer initialized to `tip`, returning a companion receiver.
    pub fn new(tip: BlockNumber) -> (Self, watch::Receiver<BlockNumber>) {
        let (tx, rx) = watch::channel(tip);
        (Self(tx), rx)
    }

    /// Returns the current proven chain tip.
    pub fn read(&self) -> BlockNumber {
        *self.0.borrow()
    }

    /// Advances the tip to `new_tip` if it is greater than the current value.
    ///
    /// Notifies all subscribers only when the tip actually increases.
    pub fn advance(&self, new_tip: BlockNumber) {
        self.0.send_if_modified(|current| {
            if new_tip > *current {
                *current = new_tip;
                true
            } else {
                false
            }
        });
    }

    /// Returns a new receiver that wakes on every proven-tip advance.
    pub fn subscribe(&self) -> watch::Receiver<BlockNumber> {
        self.0.subscribe()
    }
}

// PROVEN TIP FILE
// ================================================================================================

/// File-backed store for the proven chain tip.
///
/// Persists the proven-in-sequence tip as a little-endian `u32` (4 bytes) at the given path.
/// Writes are atomic: a temp file is written and renamed over the target.
///
/// Multiple [`ProvenTipFile`] instances at the same path are safe as long as only one writer
/// is active at a time.
#[derive(Debug, Clone)]
pub struct ProvenTipFile {
    path: PathBuf,
}

impl ProvenTipFile {
    /// Creates a new proven tip file initialised to the genesis block.
    pub fn bootstrap(path: PathBuf) -> std::io::Result<Self> {
        let file = Self { path };
        file.save(BlockNumber::GENESIS)?;
        Ok(file)
    }

    /// Opens an existing proven tip file and reads the stored tip.
    pub fn load(path: PathBuf) -> std::io::Result<(Self, BlockNumber)> {
        let tip = Self::read_from(&path)?;
        Ok((Self { path }, tip))
    }

    /// Atomically writes `tip` to the file (write to temp, then rename).
    pub fn save(&self, tip: BlockNumber) -> std::io::Result<()> {
        let tmp = self.path.with_extension("tmp");
        fs_err::write(&tmp, tip.as_u32().to_le_bytes())?;
        fs_err::rename(&tmp, &self.path)
    }

    fn read_from(path: &Path) -> std::io::Result<BlockNumber> {
        let bytes = fs_err::read(path)?;
        let arr: [u8; 4] = bytes.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "proven tip file has unexpected size (expected 4 bytes)",
            )
        })?;
        Ok(BlockNumber::from(u32::from_le_bytes(arr)))
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn advance_only_increases_tip() {
        let (writer, _rx) = ProvenTipWriter::new(BlockNumber::from(5u32));
        assert_eq!(writer.read(), BlockNumber::from(5u32));

        // Advancing to a higher value updates the tip.
        writer.advance(BlockNumber::from(10u32));
        assert_eq!(writer.read(), BlockNumber::from(10u32));

        // Advancing to a lower value is a no-op.
        writer.advance(BlockNumber::from(7u32));
        assert_eq!(writer.read(), BlockNumber::from(10u32));

        // Advancing to the same value is a no-op.
        writer.advance(BlockNumber::from(10u32));
        assert_eq!(writer.read(), BlockNumber::from(10u32));

        // Advancing to a higher value again works.
        writer.advance(BlockNumber::from(15u32));
        assert_eq!(writer.read(), BlockNumber::from(15u32));
    }

    // PROVEN TIP FILE TESTS
    // ============================================================================================

    fn load_tip(path: &std::path::Path) -> BlockNumber {
        ProvenTipFile::load(path.to_path_buf()).unwrap().1
    }

    #[test]
    fn bootstrap_initialises_to_genesis() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("proven_tip");

        ProvenTipFile::bootstrap(path.clone()).unwrap();
        assert_eq!(load_tip(&path), BlockNumber::GENESIS);
    }

    #[test]
    fn save_persists_to_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("proven_tip");
        let file = ProvenTipFile::bootstrap(path.clone()).unwrap();

        for n in [1u32, 42, 1000, u32::MAX] {
            let tip = BlockNumber::from(n);
            file.save(tip).unwrap();
            assert_eq!(load_tip(&path), tip);
        }
    }

    #[test]
    fn load_returns_last_saved_tip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("proven_tip");

        let file = ProvenTipFile::bootstrap(path.clone()).unwrap();
        let tip = BlockNumber::from(99u32);
        file.save(tip).unwrap();
        drop(file);

        let (_, loaded_tip) = ProvenTipFile::load(path).unwrap();
        assert_eq!(loaded_tip, tip);
    }

    #[test]
    fn sequential_saves_preserve_latest() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("proven_tip");
        let file = ProvenTipFile::bootstrap(path.clone()).unwrap();

        for n in 1u32..=10 {
            file.save(BlockNumber::from(n)).unwrap();
        }
        assert_eq!(load_tip(&path), BlockNumber::from(10u32));
    }

    #[test]
    fn clone_writes_to_same_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("proven_tip");
        let file = ProvenTipFile::bootstrap(path.clone()).unwrap();
        let clone = file.clone();

        file.save(BlockNumber::from(7u32)).unwrap();
        assert_eq!(load_tip(&path), BlockNumber::from(7u32));

        clone.save(BlockNumber::from(13u32)).unwrap();
        assert_eq!(load_tip(&path), BlockNumber::from(13u32));
    }

    #[test]
    fn load_missing_file_returns_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("does_not_exist");

        let result = ProvenTipFile::load(path);
        assert!(result.is_err());
    }

    #[test]
    fn load_corrupt_file_returns_invalid_data() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("proven_tip");
        // Write 3 bytes instead of 4.
        fs_err::write(&path, [0u8, 1, 2]).unwrap();

        let err = ProvenTipFile::load(path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn save_is_atomic_no_temp_file_remains() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("proven_tip");
        let file = ProvenTipFile::bootstrap(path.clone()).unwrap();

        file.save(BlockNumber::from(5u32)).unwrap();

        // The .tmp sidecar must not persist after a successful save.
        assert!(!path.with_extension("tmp").exists());
    }
}
