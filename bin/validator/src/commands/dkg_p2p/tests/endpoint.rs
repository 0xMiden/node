use super::super::{DkgP2pCommand, DkgP2pOptions};

#[tokio::test]
async fn endpoint_secret_is_private_and_not_overwritten() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let output_file = directory.path().join("endpoint.secret");
    DkgP2pOptions {
        command: DkgP2pCommand::GenerateEndpoint { output_file: output_file.clone() },
    }
    .handle()
    .await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs_err::metadata(&output_file)?.permissions().mode() & 0o777, 0o600);
    }
    let original = fs_err::read(&output_file)?;

    DkgP2pOptions {
        command: DkgP2pCommand::GenerateEndpoint { output_file: output_file.clone() },
    }
    .handle()
    .await
    .expect_err("endpoint generation must not replace an existing identity");
    assert_eq!(fs_err::read(output_file)?, original);
    Ok(())
}
