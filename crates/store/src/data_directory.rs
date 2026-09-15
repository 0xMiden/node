use std::ops::Not;
use std::path::PathBuf;

use miden_node_tracing::RecordAttribute;

/// Represents the store's data-directory and its content paths.
///
/// Used to keep our filepath assumptions in one location.
#[derive(Clone)]
pub struct DataDirectory(PathBuf);

impl DataDirectory {
    /// Creates a new [`DataDirectory`], ensuring that the directory exists and is accessible
    /// insofar as is possible.
    pub fn load(path: PathBuf) -> std::io::Result<Self> {
        let meta = fs_err::metadata(&path)?;
        if meta.is_dir().not() {
            return Err(std::io::ErrorKind::NotConnected.into());
        }

        Ok(Self(path))
    }

    pub fn block_store_dir(&self) -> PathBuf {
        self.0.join("blocks")
    }

    pub fn database_path(&self) -> PathBuf {
        self.0.join("miden-store.sqlite3")
    }

    pub fn allowlist_database_path(&self) -> PathBuf {
        self.0.join("miden-allowlist.sqlite3")
    }

    pub fn display(&self) -> std::path::Display<'_> {
        self.0.display()
    }
}

impl RecordAttribute for DataDirectory {
    const FIELD_NAMES: &'static [&'static str] = &["data.directory", "path"];

    fn record_attribute(&self) -> impl miden_node_tracing::Value + '_ {
        miden_node_tracing::field::display(self.display())
    }
}
