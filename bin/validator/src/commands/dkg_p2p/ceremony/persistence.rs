use std::io::Write;

use anyhow::{Context, ensure};
use fs_err::PathExt;
use golden_ehtdh1::Ehtdh1Material;
use miden_validator::{DataDirectory, GoldenOperatorKey};

use super::Ceremony;
use super::dkg::StorageGroup;

impl Ceremony {
    /// Writes the validator startup bundle without replacing an existing storage key.
    pub fn persist(
        &self,
        data_directory: &DataDirectory,
        output: Ehtdh1Material<StorageGroup>,
    ) -> anyhow::Result<()> {
        let output_directory = data_directory.storage_key_dir();
        ensure!(
            !output_directory.fs_err_try_exists()?,
            "storage key directory already exists: {}",
            output_directory.display(),
        );
        let operator_key = GoldenOperatorKey::new(
            self.epoch,
            output.setup_context,
            output.public_key_set,
            output.secret_share,
        )
        .context("generated invalid storage key material")?;
        let (epoch, setup_context, public_key_set, secret_share) =
            operator_key.encode().into_parts();
        let epoch = hex::encode(epoch.as_bytes());

        // Stage the complete bundle on the same filesystem before making it available to startup.
        let parent = output_directory.parent().expect("storage key is inside the data directory");
        let mut temporary = tempfile::Builder::new();
        temporary.prefix(".storage-key-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temporary.permissions(std::fs::Permissions::from_mode(0o700));
        }
        let temporary = temporary
            .tempdir_in(parent)
            .context("failed to create temporary storage key directory")?;
        for (name, bytes) in [
            ("epoch.hex", epoch.as_bytes()),
            ("setup-context.wire", setup_context.as_slice()),
            ("public-key-set.wire", public_key_set.as_slice()),
            ("secret-share.wire", secret_share.as_slice()),
        ] {
            let path = temporary.path().join(name);
            let mut options = std::fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&path)
                .with_context(|| format!("failed to create {}", path.display()))?;
            file.write_all(bytes)
                .with_context(|| format!("failed to write {}", path.display()))?;
            file.sync_all().with_context(|| format!("failed to sync {}", path.display()))?;
        }
        #[cfg(unix)]
        fs_err::File::open(temporary.path())?
            .sync_all()
            .context("failed to sync storage key directory")?;
        fs_err::rename(temporary.path(), &output_directory)
            .context("failed to move storage key bundle into place")?;
        #[cfg(unix)]
        fs_err::File::open(parent)?
            .sync_all()
            .context("failed to sync validator data directory")?;
        Ok(())
    }
}
