use std::path::Path;

use anyhow::Context;
use miden_validator::{GoldenOperatorKey, PrivateRecordShareRequest, StoredPrivateRecord};
use rand_core_06::OsRng;

use super::PrivateRecordShareOptions;

/// Loads the required operator key and issues one administrative share.
pub(super) fn issue_from_options(options: PrivateRecordShareOptions) -> anyhow::Result<()> {
    let PrivateRecordShareOptions { record, output, storage_key } = options;
    let operator_key = storage_key.load()?;
    issue(&record, &output, &operator_key)
}

/// Issues this validator's canonical share for one checked private record.
pub(super) fn issue(
    record_path: &Path,
    output: &Path,
    operator_key: &GoldenOperatorKey,
) -> anyhow::Result<()> {
    let record_bytes = fs_err::read(record_path).with_context(|| {
        format!("failed to read private record bundle from {}", record_path.display())
    })?;
    let record = miden_node_persistence::decode::<StoredPrivateRecord>(&record_bytes)
        .context("private record bundle is invalid")?;

    let request = PrivateRecordShareRequest::for_record(&record);
    let share = operator_key
        .issue_private_record_share(&mut OsRng, &request, &record)
        .context("failed to issue private record share")?;

    write_share(output, &share)
}

/// Writes canonical share bytes without adding a text encoding or delimiter.
fn write_share(output: &Path, share: &[u8]) -> anyhow::Result<()> {
    fs_err::write(output, share)
        .with_context(|| format!("failed to write private record share to {}", output.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_output_preserves_share_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("share.bin");
        let share = [0, 1, 2, 3, 0xff];

        write_share(&output, &share).unwrap();

        assert_eq!(fs_err::read(output).unwrap(), share);
    }
}
