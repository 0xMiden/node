use super::*;

#[test]
fn saves_the_collector_signing_key_without_overwriting_existing_files() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fee-collector.mac");
    CreateCommand {
        data_directory: directory.path().to_path_buf(),
    }
    .handle()?;
    let account_file = AccountFile::read(&path)?;
    let loaded = FeeCollectorAccountOptions { account: None }.read(directory.path())?;
    assert_eq!(loaded.to_bytes(), account_file.to_bytes());
    assert!(account_file.account().is_new());
    assert!(account_file.account().is_public());
    assert!(account_file.account().vault().is_empty());
    assert_eq!(account_file.auth_secret_keys().len(), 1);
    assert_eq!(
        account_file
            .account()
            .storage()
            .get_item(AuthTxFeeCollector::public_key_slot())?,
        miden_protocol::Word::from(account_file.auth_secret_keys()[0].public_key().to_commitment()),
    );
    let contents = fs_err::read(&path)?;
    assert!(
        CreateCommand {
            data_directory: directory.path().to_path_buf()
        }
        .handle()
        .is_err()
    );
    assert_eq!(fs_err::read(&path)?, contents);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs_err::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    }
    Ok(())
}

#[test]
fn explicit_account_file_overrides_the_data_directory_default() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let other_directory = tempfile::tempdir()?;
    CreateCommand {
        data_directory: directory.path().to_path_buf(),
    }
    .handle()?;
    CreateCommand {
        data_directory: other_directory.path().to_path_buf(),
    }
    .handle()?;
    let default_path = directory.path().join("fee-collector.mac");
    let custom_path = other_directory.path().join("fee-collector.mac");
    let default_contents = fs_err::read(&default_path)?;
    let custom_contents = fs_err::read(&custom_path)?;
    let account =
        FeeCollectorAccountOptions { account: Some(custom_path.clone()) }.read(directory.path())?;
    assert_eq!(account.to_bytes(), custom_contents);
    assert_ne!(account.account().id(), AccountFile::read(&default_path)?.account().id());
    assert_eq!(fs_err::read(default_path)?, default_contents);
    assert_eq!(fs_err::read(custom_path)?, custom_contents);
    Ok(())
}
