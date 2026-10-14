use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use miden_validator::{
    GoldenOperatorKey,
    PrivateRecordCombiner,
    PrivateRecordShareRequest,
    StoredPrivateRecord,
};

use super::PrivateRecordDecryptOptions;

/// Loads matching storage-key material and recovers an exported record.
pub(super) fn decrypt_from_options(options: PrivateRecordDecryptOptions) -> anyhow::Result<()> {
    let operator_key = options.storage_key.load()?;
    decrypt(&options.record, &options.shares, &options.output, &operator_key)
}

/// Authenticates the record and shares before replacing the output with plaintext bytes.
pub(super) fn decrypt(
    record_path: &Path,
    share_paths: &[PathBuf],
    output: &Path,
    operator_key: &GoldenOperatorKey,
) -> anyhow::Result<()> {
    let record_bytes = fs_err::read(record_path).with_context(|| {
        format!("failed to read private record bundle from {}", record_path.display())
    })?;
    let record = miden_node_persistence::decode::<StoredPrivateRecord>(&record_bytes)
        .context("private record bundle is invalid")?;
    let shares = share_paths
        .iter()
        .map(|path| {
            fs_err::read(path).with_context(|| {
                format!("failed to read private record share from {}", path.display())
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let combiner = PrivateRecordCombiner::from_operator_key(operator_key)
        .context("failed to initialize record decryption")?;
    let plaintext = combiner
        .open(&PrivateRecordShareRequest::for_record(&record), &record, &shares)
        .context("failed to decrypt private record")?;
    write_plaintext(output, plaintext.as_slice())
        .with_context(|| format!("failed to write decrypted record to {}", output.display()))
}

/// Replaces the output with a complete, owner-only plaintext file.
///
/// The plaintext is private transaction data, so it must never be readable by other users or
/// visible at the output path in part. Writing a temporary file in the destination directory
/// keeps both files on one filesystem, which makes the final rename atomic.
fn write_plaintext(output: &Path, plaintext: &[u8]) -> anyhow::Result<()> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::Builder::new();
    temporary.prefix(".private-record-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary.permissions(std::fs::Permissions::from_mode(0o600));
    }
    let mut temporary = temporary
        .tempfile_in(parent)
        .context("failed to create temporary plaintext file")?;
    temporary
        .write_all(plaintext)
        .context("failed to write temporary plaintext file")?;
    temporary
        .as_file()
        .sync_all()
        .context("failed to sync temporary plaintext file")?;
    temporary.persist(output).context("failed to move plaintext file into place")?;
    Ok(())
}
