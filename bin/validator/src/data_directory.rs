use std::ops::Not;
use std::path::PathBuf;

/// Represents the validator's data directory and its content paths.
///
/// Used to keep our filepath assumptions in one location.
#[derive(Clone)]
pub struct DataDirectory {
    data: PathBuf,
}

impl DataDirectory {
    /// Loads the data directory, verifying that it exists.
    pub fn load(data: PathBuf) -> std::io::Result<Self> {
        if fs_err::metadata(&data)?.is_dir().not() {
            return Err(std::io::ErrorKind::NotConnected.into());
        }
        Ok(Self { data })
    }

    pub fn database_path(&self) -> PathBuf {
        self.data.join("validator.sqlite3")
    }

    pub fn block_store_dir(&self) -> PathBuf {
        self.data.join("blocks")
    }

    pub fn display(&self) -> std::path::Display<'_> {
        self.data.display()
    }
}
