use std::collections::BTreeMap;
use std::path::Path;

use golden_core::{GoldenGroup, GoldenScalar, ParticipantIndex, SessionId};
use golden_ehtdh1::wire::{from_wire_bytes, to_wire_bytes};
use golden_ehtdh1::{
    DecryptionShare,
    PublicKeySet,
    PublicShare,
    SecretShare,
    SetupContext,
    derive_context_session_id,
};
use golden_halo2curves::golden_group::{Secp256k1GoldenGroup, Secp256k1Scalar};
use miden_protocol::Word;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::transaction::{TransactionId, TransactionInputs};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_testing::{Auth, MockChainBuilder};
use rand_chacha_03::ChaCha20Rng;
use rand_chacha_03::rand_core::SeedableRng;

use super::*;

type TestStorageGroup = Secp256k1GoldenGroup;

const TEST_SIGNING_KEY_HEX: &str =
    "0101010101010101010101010101010101010101010101010101010101010101";
const TEST_ENCRYPTION_KEY_HEX: &str =
    "0202020202020202020202020202020202020202020202020202020202020202";

const BASE_START_ARGS: [&str; 8] = [
    "miden-validator",
    "start",
    "--listen",
    "127.0.0.1:50101",
    "--data-directory",
    "/tmp/validator-data",
    "--signing-key.hex",
    TEST_SIGNING_KEY_HEX,
];
const ENCRYPTION_KEY_ARGS: [&str; 2] = ["--encryption-key.hex", TEST_ENCRYPTION_KEY_HEX];
const STORAGE_KEY_ARGS: [&str; 8] = [
    "--storage-key.epoch",
    "0909090909090909090909090909090909090909090909090909090909090909",
    "--storage-key.setup-context",
    "/tmp/setup.bin",
    "--storage-key.public-key-set",
    "/tmp/public.bin",
    "--storage-key.secret-share",
    "/tmp/secret.bin",
];

fn parse_start(extra: &[&str]) -> Result<ValidatorCommand, clap::Error> {
    ValidatorCommand::try_parse_from(
        BASE_START_ARGS
            .iter()
            .copied()
            .chain(extra.iter().copied())
            .chain(STORAGE_KEY_ARGS.iter().copied()),
    )
}
fn test_operator_keys(epoch: u8, setup_marker: u8) -> Vec<GoldenOperatorKey> {
    let participants = [1, 2, 3].map(|value| ParticipantIndex::new(value).unwrap());
    let decryption_secret = Secp256k1Scalar::from_u64(11).unwrap();
    let decryption_coefficient = Secp256k1Scalar::from_u64(7).unwrap();
    let context_coefficient = Secp256k1Scalar::from_u64(13).unwrap();
    let mut public_shares = BTreeMap::new();
    let secret_shares = participants.map(|participant| {
        let point = participant.to_scalar::<Secp256k1Scalar>().unwrap();
        let decryption = decryption_secret.add(&decryption_coefficient.mul(&point));
        let context = context_coefficient.mul(&point);
        public_shares.insert(
            participant,
            PublicShare {
                decryption: TestStorageGroup::mul_generator(&decryption),
                context: TestStorageGroup::mul_generator(&context),
            },
        );
        SecretShare { participant, decryption, context }
    });
    let public_key_set =
        PublicKeySet::new(2, TestStorageGroup::mul_generator(&decryption_secret), public_shares)
            .unwrap();
    let decryption_session_id = SessionId([2; 32]);
    let setup_context = SetupContext {
        backend_id: TestStorageGroup::BACKEND_ID.to_owned(),
        threshold: 2,
        registry_root: [1; 32],
        participants: participants.to_vec(),
        decryption_session_id,
        context_session_id: derive_context_session_id(decryption_session_id),
        decryption_transcript_root: [setup_marker; 32],
        context_transcript_root: [4; 32],
        epoch: [epoch; 32],
    };
    secret_shares
        .into_iter()
        .map(|secret_share| {
            GoldenOperatorKey::new(
                StorageKeyEpoch::new([epoch; 32]),
                setup_context.clone(),
                public_key_set.clone(),
                secret_share,
            )
            .unwrap()
        })
        .collect()
}

fn transaction_inputs() -> TransactionInputs {
    let mut builder = MockChainBuilder::new();
    let account = builder
        .add_existing_wallet(Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        })
        .unwrap();
    builder.build().unwrap().get_transaction_inputs(&account, &[], &[]).unwrap()
}

fn issue_error(record: &Path, output: &Path, operator_key: &GoldenOperatorKey) -> String {
    let error = issue_private_record_share::issue(record, output, operator_key).unwrap_err();
    format!("{error:#}")
}

fn assert_issue_error(
    record: &Path,
    output: &Path,
    operator_key: &GoldenOperatorKey,
    expected: &str,
) {
    let error = issue_error(record, output, operator_key);
    assert!(error.contains(expected), "expected {expected:?} in {error:?}");
}

fn issue_share_file(record: &Path, output: &Path, operator_key: &GoldenOperatorKey) -> Vec<u8> {
    issue_private_record_share::issue(record, output, operator_key).unwrap();
    fs_err::read(output).unwrap()
}

async fn store_private_record(
    writer: &miden_validator::db::ValidatorDbWriter,
    record: miden_validator::StoredPrivateRecord,
) {
    writer.insert_validated_private_transaction(record).await.unwrap();
}

async fn export_record_file(
    data_directory: &Path,
    encoded_transaction_id: &str,
    encoded_validator_id: &str,
    output: &Path,
) {
    export_private_record::export(PrivateRecordExportOptions {
        data_directory: data_directory.to_path_buf(),
        transaction_id: encoded_transaction_id.to_owned(),
        validator_id: encoded_validator_id.to_owned(),
        output: output.to_path_buf(),
    })
    .await
    .unwrap();
}

const BASE_GENESIS_ARGS: [&str; 6] = [
    "miden-validator",
    "genesis",
    "--genesis-block-directory",
    "/tmp/genesis",
    "--accounts-directory",
    "/tmp/accounts",
];

fn parse_genesis(extra: &[&str]) -> Result<ValidatorCommand, clap::Error> {
    ValidatorCommand::try_parse_from(BASE_GENESIS_ARGS.iter().copied().chain(extra.iter().copied()))
}

#[test]
fn genesis_validator_keys_parse_from_repeated_flags() {
    let keys = [7u8, 8].map(|seed| {
        SigningKey::read_from_bytes(&[seed; 32]).expect("test signing key should decode")
    });
    let hex_keys = keys.clone().map(|key| hex::encode(key.public_key().to_bytes()));
    let command =
        parse_genesis(&["--validator.key", &hex_keys[0], "--validator.key", &hex_keys[1]])
            .expect("genesis with explicit validator keys must parse");
    let ValidatorCommand::Genesis { validator_keys, .. } = command else {
        panic!("expected the genesis command");
    };
    assert_eq!(validator_keys, keys.map(|key| key.public_key()).to_vec());
}

#[test]
fn genesis_requires_an_explicit_validator_set() {
    let Err(error) = parse_genesis(&[]) else {
        panic!("genesis without an explicit validator set must be rejected");
    };
    assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);

    let key = SigningKey::read_from_bytes(&[7; 32]).expect("test signing key should decode");
    let key_hex = hex::encode(key.public_key().to_bytes());
    parse_genesis(&["--config", "/tmp/genesis.toml", "--validator.key", &key_hex])
        .expect("--config with an explicit validator set must parse");
}

#[test]
fn genesis_rejects_an_invalid_validator_key() {
    let Err(error) = parse_genesis(&["--validator.key", "not-hex"]) else {
        panic!("an invalid validator key must be rejected");
    };
    assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
}

#[test]
fn encryption_key_is_required() {
    let Err(error) = parse_start(&[]) else {
        panic!("start without an encryption key must be rejected");
    };
    assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[test]
fn signing_key_is_required() {
    let Err(error) = ValidatorCommand::try_parse_from(
        ["miden-validator", "start", "--listen", "127.0.0.1:50101"]
            .into_iter()
            .chain(["--data-directory", "/tmp/validator-data"])
            .chain(ENCRYPTION_KEY_ARGS)
            .chain(STORAGE_KEY_ARGS),
    ) else {
        panic!("start without a signing key must be rejected");
    };
    assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[test]
fn admin_listener_is_opt_in() {
    let command =
        parse_start(&ENCRYPTION_KEY_ARGS).expect("start without an admin listener must parse");
    let ValidatorCommand::Start { admin_listen, .. } = command else {
        panic!("expected the start command");
    };
    assert_eq!(admin_listen, None);

    let command = parse_start(
        &[ENCRYPTION_KEY_ARGS.as_slice(), &["--admin.listen", "127.0.0.1:50102"]].concat(),
    )
    .expect("start with an admin listener must parse");
    let ValidatorCommand::Start { admin_listen, .. } = command else {
        panic!("expected the start command");
    };
    assert_eq!(admin_listen, Some("127.0.0.1:50102".parse().unwrap()));
}

#[test]
fn encryption_key_kms_ciphertext_parses_alone() {
    let command = parse_start(&["--encryption-key.kms-ciphertext", "deadbeef"])
        .expect("KMS ciphertext without a hex key must parse");
    let ValidatorCommand::Start { encryption_key, .. } = command else {
        panic!("expected the start command");
    };
    assert_eq!(encryption_key.encryption_key_kms_ciphertext.as_deref(), Some("deadbeef"));
    assert_eq!(encryption_key.encryption_key, None);
}

#[test]
fn encryption_key_hex_and_kms_ciphertext_conflict() {
    let result = parse_start(&[
        "--encryption-key.hex",
        TEST_ENCRYPTION_KEY_HEX,
        "--encryption-key.kms-ciphertext",
        "deadbeef",
    ]);
    let Err(error) = result else {
        panic!("hex key and KMS ciphertext together must be rejected");
    };
    assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn storage_key_is_required() {
    let Err(error) =
        ValidatorCommand::try_parse_from(BASE_START_ARGS.into_iter().chain(ENCRYPTION_KEY_ARGS))
    else {
        panic!("start without a storage key must fail");
    };
    assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[test]
fn partial_storage_key_configuration_fails() {
    let Err(error) = ValidatorCommand::try_parse_from(
        BASE_START_ARGS.into_iter().chain(ENCRYPTION_KEY_ARGS).chain([
            "--storage-key.epoch",
            "0909090909090909090909090909090909090909090909090909090909090909",
        ]),
    ) else {
        panic!("a partial storage key must fail");
    };
    assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[test]
fn keygen_command_parses() {
    let command = ValidatorCommand::try_parse_from(["miden-validator", "keygen"])
        .expect("the keygen command must parse");
    assert!(matches!(command, ValidatorCommand::Keygen));
}

#[test]
fn private_record_share_command_parses() {
    let command = ValidatorCommand::try_parse_from([
        "miden-validator",
        "issue-private-record-share",
        "--record",
        "/tmp/record.bin",
        "--output",
        "/tmp/share.bin",
        "--storage-key.epoch",
        "0909090909090909090909090909090909090909090909090909090909090909",
        "--storage-key.setup-context",
        "/tmp/setup.bin",
        "--storage-key.public-key-set",
        "/tmp/public.bin",
        "--storage-key.secret-share",
        "/tmp/secret.bin",
    ])
    .expect("the local share command must parse");

    let ValidatorCommand::IssuePrivateRecordShare(PrivateRecordShareOptions {
        record, output, ..
    }) = command
    else {
        panic!("expected the private record share command");
    };
    assert_eq!(record, PathBuf::from("/tmp/record.bin"));
    assert_eq!(output, PathBuf::from("/tmp/share.bin"));
}

#[test]
fn private_record_export_command_parses() {
    let validator_id = SigningKey::read_from_bytes(&[7; 32]).unwrap().public_key().to_bytes();
    let command = ValidatorCommand::try_parse_from([
        "miden-validator",
        "export-private-record",
        "--data-directory",
        "/tmp/validator-data",
        "--transaction-id",
        "0101010101010101010101010101010101010101010101010101010101010101",
        "--validator-id",
        &hex::encode(validator_id),
        "--output",
        "/tmp/record.bin",
    ])
    .expect("the private record export command must parse");

    let ValidatorCommand::ExportPrivateRecord(PrivateRecordExportOptions {
        data_directory,
        transaction_id,
        output,
        ..
    }) = command
    else {
        panic!("expected the private record export command");
    };
    assert_eq!(data_directory, PathBuf::from("/tmp/validator-data"));
    assert_eq!(
        transaction_id,
        "0101010101010101010101010101010101010101010101010101010101010101",
    );
    assert_eq!(output, PathBuf::from("/tmp/record.bin"));
}

#[test]
fn private_record_share_output_is_required() {
    let result = ValidatorCommand::try_parse_from([
        "miden-validator",
        "issue-private-record-share",
        "--record",
        "/tmp/record.bin",
        "--storage-key.epoch",
        "0909090909090909090909090909090909090909090909090909090909090909",
        "--storage-key.setup-context",
        "/tmp/setup.bin",
        "--storage-key.public-key-set",
        "/tmp/public.bin",
        "--storage-key.secret-share",
        "/tmp/secret.bin",
    ]);

    let Err(error) = result else {
        panic!("share output must be explicit");
    };
    assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[tokio::test]
async fn two_validators_issue_shares_for_third_validator_record() {
    let directory = tempfile::tempdir().unwrap();
    let writer = miden_validator::db::setup(directory.path().join("validator.sqlite3"))
        .await
        .unwrap();
    let operator_keys = test_operator_keys(9, 3);
    let validator_signers = [7u8, 8, 9].map(|seed| {
        SigningKey::read_from_bytes(&[seed; 32]).expect("test signing key should decode")
    });
    let transaction_id = TransactionId::from_raw(Word::from([1u32, 2, 3, 4]));
    let inputs = transaction_inputs();
    let mut records = Vec::new();
    for (index, signer) in validator_signers.iter().enumerate() {
        let record_id = miden_validator::PrivateRecordId::new(transaction_id, &signer.public_key());
        let context = miden_validator::PrivateRecordContext::new(
            miden_validator::PrivateRecordChainId::new([5; 32]),
            operator_keys[index].key_epoch(),
            transaction_id,
        );
        let mut rng = ChaCha20Rng::from_seed([6 + index as u8; 32]);
        records.push(
            miden_validator::PrivateRecordSealer::from_operator_key(&operator_keys[index])
                .seal(&mut rng, record_id, context, &inputs.to_bytes())
                .unwrap(),
        );
    }
    assert_ne!(records[0].record_id(), records[1].record_id());
    assert_ne!(records[1].record_id(), records[2].record_id());
    assert_ne!(records[0].encrypted_record_key(), records[1].encrypted_record_key());
    assert_ne!(records[1].encrypted_record_key(), records[2].encrypted_record_key());

    let target = records.remove(2);
    store_private_record(&writer, target.clone()).await;
    let target_file = directory.path().join("target-record.bin");
    let encoded_transaction_id = hex::encode(transaction_id.to_bytes());
    let encoded_validator_id = hex::encode(target.record_id().validator_id());
    export_record_file(
        directory.path(),
        &encoded_transaction_id,
        &encoded_validator_id,
        &target_file,
    )
    .await;
    assert_eq!(
        miden_validator::StoredPrivateRecord::read_from_bytes(&fs_err::read(&target_file).unwrap())
            .unwrap(),
        target,
    );

    let first_output = directory.path().join("share-1.bin");
    let second_output = directory.path().join("share-2.bin");
    let first_share = issue_share_file(&target_file, &first_output, &operator_keys[0]);
    let second_share = issue_share_file(&target_file, &second_output, &operator_keys[1]);
    let shares = [first_share, second_share];
    for share in &shares {
        let decoded = from_wire_bytes::<DecryptionShare<TestStorageGroup>>(share).unwrap();
        assert_eq!(to_wire_bytes(&decoded), *share);
    }
    let request = miden_validator::PrivateRecordShareRequest::for_record(&target);
    let opened = miden_validator::PrivateRecordCombiner::from_operator_key(&operator_keys[2])
        .unwrap()
        .open(&request, &target, &shares)
        .unwrap();
    assert_eq!(TransactionInputs::read_from_bytes(&opened).unwrap(), inputs);

    let wrong_epoch = test_operator_keys(10, 3).remove(0);
    assert_issue_error(&target_file, &first_output, &wrong_epoch, "key epoch does not match");

    let wrong_setup = test_operator_keys(9, 7).remove(0);
    assert_issue_error(&target_file, &first_output, &wrong_setup, "setup does not match");

    let missing_validator_id = hex::encode(validator_signers[0].public_key().to_bytes());
    let error = export_private_record::export(PrivateRecordExportOptions {
        data_directory: directory.path().to_path_buf(),
        transaction_id: encoded_transaction_id,
        validator_id: missing_validator_id,
        output: target_file,
    })
    .await;
    assert!(format!("{:#}", error.unwrap_err()).contains("was not found"));
}
