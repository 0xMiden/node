use std::path::Path;

use miden_validator::EncodedGoldenOperatorKey;
use zeroize::Zeroizing;

use super::super::{DkgCommand, DkgOptions};

#[tokio::test]
async fn committed_fixture_has_one_valid_share_per_participant() -> anyhow::Result<()> {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/testdata/insecure-storage-key");
    let mut shares = Vec::new();

    for participant in 1..=3 {
        let bundle_file = fixture.join(format!("validator-{participant}/storage-key.bundle"));
        DkgOptions {
            command: DkgCommand::ValidateFixture {
                bundle_file: bundle_file.clone(),
                expected_participant: participant,
            },
        }
        .handle()
        .await?;
        let bytes = Zeroizing::new(fs_err::read(bundle_file)?);
        shares.push(EncodedGoldenOperatorKey::from_bytes(&bytes)?.into_parts().3);
    }

    assert_ne!(shares[0], shares[1]);
    assert_ne!(shares[1], shares[2]);
    assert_ne!(shares[0], shares[2]);
    Ok(())
}

#[tokio::test]
async fn fixture_rejects_another_participants_bundle() -> anyhow::Result<()> {
    let bundle_file = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/testdata/insecure-storage-key/validator-1/storage-key.bundle");
    let error = DkgOptions {
        command: DkgCommand::ValidateFixture { bundle_file, expected_participant: 2 },
    }
    .handle()
    .await
    .expect_err("a valid bundle from another participant must not be accepted");

    assert_eq!(error.to_string(), "fixture belongs to participant 1, expected 2");
    Ok(())
}
