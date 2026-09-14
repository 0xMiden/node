use std::io::Write;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, ensure};
use iroh::SecretKey;
use iroh_docs::api::Doc;

use super::super::super::{decode_fixed_hex, publish_directory, sync_directory, write_new_file};

pub(super) const ENDPOINT_SECRET_FILE: &str = "endpoint-secret.hex";
pub(super) const BOARD_METADATA_DIRECTORY: &str = "board-meta";
pub(super) const DOCUMENT_ID_FILE: &str = "document-id.hex";
pub(super) const BOARD_FORMAT_FILE: &str = "board-format";
const BOARD_FORMAT: &[u8] = b"participant-upload-v4\n";
pub(super) const UPLOAD_SECRETS_DIRECTORY: &str = "upload-secrets";

pub(super) fn load_or_create_endpoint_secret(data_directory: &Path) -> anyhow::Result<SecretKey> {
    let path = data_directory.join(ENDPOINT_SECRET_FILE);
    if path.exists() {
        let encoded = fs_err::read_to_string(&path)
            .with_context(|| format!("failed to read Iroh endpoint secret {}", path.display()))?;
        return SecretKey::from_str(encoded.trim()).context("invalid Iroh endpoint secret");
    }

    let secret = SecretKey::generate();
    let mut temporary = tempfile::Builder::new()
        .prefix(".endpoint-secret-")
        .tempfile_in(data_directory)
        .context("failed to create temporary Iroh endpoint secret")?;
    temporary
        .write_all(hex::encode(secret.to_bytes()).as_bytes())
        .context("failed to write temporary Iroh endpoint secret")?;
    temporary
        .as_file()
        .sync_all()
        .context("failed to sync temporary Iroh endpoint secret")?;
    temporary
        .persist_noclobber(&path)
        .map_err(|error| error.error)
        .with_context(|| format!("failed to publish Iroh endpoint secret {}", path.display()))?;
    sync_directory(data_directory)?;
    Ok(secret)
}

pub(super) fn publish_board_metadata(
    path: &Path,
    document: &Doc,
    upload_secrets: &[[u8; 32]],
) -> anyhow::Result<()> {
    publish_directory(path, |temporary| {
        write_new_file(
            &temporary.join(DOCUMENT_ID_FILE),
            hex::encode(document.id().to_bytes()).as_bytes(),
            true,
        )?;
        write_new_file(&temporary.join(BOARD_FORMAT_FILE), BOARD_FORMAT, true)?;
        let upload_secrets_directory = temporary.join(UPLOAD_SECRETS_DIRECTORY);
        fs_err::create_dir(&upload_secrets_directory).with_context(|| {
            format!(
                "failed to create DKG board upload secrets {}",
                upload_secrets_directory.display()
            )
        })?;
        for (position, secret) in upload_secrets.iter().enumerate() {
            write_new_file(
                &upload_secrets_directory.join(format!("participant-{}.hex", position + 1)),
                hex::encode(secret).as_bytes(),
                true,
            )?;
        }
        Ok(())
    })
}

pub(super) fn load_upload_secrets(
    metadata_directory: &Path,
    participant_count: usize,
) -> anyhow::Result<Vec<[u8; 32]>> {
    let path = metadata_directory.join(UPLOAD_SECRETS_DIRECTORY);
    let entry_count = fs_err::read_dir(&path)
        .with_context(|| format!("failed to read DKG board upload secrets {}", path.display()))?
        .collect::<Result<Vec<_>, _>>()?
        .len();
    ensure!(
        entry_count == participant_count,
        "DKG board upload secret count does not match the participant count"
    );
    (1..=participant_count)
        .map(|participant| {
            let secret_path = path.join(format!("participant-{participant}.hex"));
            let bytes = fs_err::read_to_string(&secret_path).with_context(|| {
                format!("failed to read DKG board upload secret {}", secret_path.display())
            })?;
            decode_fixed_hex::<32>(bytes.trim(), "DKG board upload secret")
        })
        .collect()
}

pub(super) fn require_current_board_format(metadata_directory: &Path) -> anyhow::Result<()> {
    let path = metadata_directory.join(BOARD_FORMAT_FILE);
    let format = fs_err::read(&path)
        .with_context(|| format!("failed to read DKG board format {}", path.display()))?;
    ensure!(
        format == BOARD_FORMAT,
        "unsupported DKG board format; start a new ceremony in a new data directory"
    );
    Ok(())
}
