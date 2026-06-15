use std::ops::Not;
use std::path::{Path, PathBuf};

/// Represents the validator's directories and their content paths.
///
/// Used to keep our filepath assumptions in one location.
#[derive(Clone)]
pub enum DataDirectory {
    /// Runtime mode: just the data directory.
    Server { data: PathBuf },
    /// Bootstrap mode: genesis block, accounts, and data directories.
    Bootstrap {
        genesis_block: PathBuf,
        accounts: PathBuf,
        data: PathBuf,
    },
}

impl DataDirectory {
    /// Loads a data directory for use by the `start` and `migrate` commands.
    pub fn load_server(data: PathBuf) -> std::io::Result<Self> {
        verify_is_dir(&data)?;
        Ok(Self::Server { data })
    }

    /// Loads a data directory for use by the `bootstrap` command.
    pub fn load_bootstrap(
        genesis_block: PathBuf,
        accounts: PathBuf,
        data: PathBuf,
    ) -> std::io::Result<Self> {
        for dir in [&genesis_block, &accounts, &data] {
            verify_is_dir(dir)?;
        }
        Ok(Self::Bootstrap { genesis_block, accounts, data })
    }

    pub fn database_path(&self) -> PathBuf {
        self.data().join("validator.sqlite3")
    }

    pub fn block_store_dir(&self) -> PathBuf {
        self.data().join("blocks")
    }

    pub fn genesis_block_path(&self) -> Option<PathBuf> {
        match self {
            Self::Bootstrap { genesis_block, .. } => Some(genesis_block.join("genesis.dat")),
            Self::Server { .. } => None,
        }
    }

    pub fn accounts_dir(&self) -> Option<&Path> {
        match self {
            Self::Bootstrap { accounts, .. } => Some(accounts),
            Self::Server { .. } => None,
        }
    }

    pub fn display(&self) -> std::path::Display<'_> {
        self.data().display()
    }

    fn data(&self) -> &PathBuf {
        match self {
            Self::Server { data } | Self::Bootstrap { data, .. } => data,
        }
    }
}

fn verify_is_dir(path: &PathBuf) -> std::io::Result<()> {
    if fs_err::metadata(path)?.is_dir().not() {
        return Err(std::io::ErrorKind::NotConnected.into());
    }
    Ok(())
}
