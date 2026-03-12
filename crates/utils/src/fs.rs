use std::path::Path;

use anyhow::Context;

/// Validates that a directory either does not exist (and creates it) or exists and is empty.
pub fn ensure_empty_directory(directory: &Path) -> anyhow::Result<()> {
    if fs_err::exists(directory)? {
        let is_empty = fs_err::read_dir(directory)?.next().is_none();
        anyhow::ensure!(is_empty, "{} exists but is not empty", directory.display());
    } else {
        fs_err::create_dir(directory).with_context(|| {
            format!(
                "failed to create {} at {}",
                directory.file_name().unwrap_or(std::ffi::OsStr::new("directory")).display(),
                directory.display()
            )
        })?;
    }
    Ok(())
}
