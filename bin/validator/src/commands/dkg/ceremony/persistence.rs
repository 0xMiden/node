use std::io::Write;
use std::path::Path;

use anyhow::{Context, ensure};
use fs_err::PathExt;
use golden_ehtdh1::Ehtdh1Material;
use miden_validator::GoldenOperatorKey;

use super::Ceremony;
use super::dkg::StorageGroup;

impl Ceremony {
    /// Writes a validated storage-key bundle to a new file without replacing an existing file.
    ///
    /// Success here only confirms local persistence. The command must still receive matching peer
    /// completion messages before reporting that the bundle is safe to use.
    pub fn persist(
        &self,
        output_file: &Path,
        output: Ehtdh1Material<StorageGroup>,
    ) -> anyhow::Result<()> {
        ensure!(
            !output_file.fs_err_try_exists()?,
            "storage key bundle already exists: {}",
            output_file.display(),
        );
        let operator_key = GoldenOperatorKey::new(
            self.epoch,
            output.setup_context,
            output.public_key_set,
            output.secret_share,
        )
        .context("generated invalid storage key material")?;
        let bytes = operator_key.encode().to_bytes();

        // Write and sync a temporary bundle in the destination directory.
        //
        // The final path must not expose a partial bundle. Keeping both files on the same
        // filesystem allows atomic publication of the complete bundle.
        let parent = output_file
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut temporary = tempfile::Builder::new();
        temporary.prefix(".storage-key-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temporary.permissions(std::fs::Permissions::from_mode(0o600));
        }
        let mut temporary = temporary
            .tempfile_in(parent)
            .context("failed to create temporary storage key bundle")?;
        temporary.write_all(&bytes).context("failed to write storage key bundle")?;
        temporary.as_file().sync_all().context("failed to sync storage key bundle")?;
        temporary
            .persist_noclobber(output_file)
            .context("failed to move storage key bundle into place")?;
        #[cfg(unix)]
        fs_err::File::open(parent)?
            .sync_all()
            .context("failed to sync storage key output directory")?;
        Ok(())
    }
}
