use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, ensure};
use golden_core::{EvrfProofBackend, ParticipantIndex};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_validator::ValidatorSigner;

use super::board::{
    ArtifactSlot,
    BoardReader,
    BoardTicket,
    CommonArtifact,
    CoordinatorBoard,
    ParticipantArtifact,
    ParticipantBoard,
};
use super::{
    CONTEXT_CONFIG_FILE,
    CONTEXT_DEALING_FILE,
    DECRYPTION_CONFIG_FILE,
    DECRYPTION_DEALING_FILE,
    GoldenGroup,
    IDENTITY_SECRET_FILE,
    MANIFEST_FILE,
    OsRng,
    PRIVATE_STATE_FILE,
    REGISTRATION_FILE,
    Registration,
    SecpSecqBackend,
    Serializable,
    StorageGroup,
    TRANSCRIPT_ACCEPTANCE_FILE,
    TRANSCRIPT_FILE,
    ValidatorSigningKey,
    Zeroizing,
    accept_transcript,
    deal,
    decode_fixed_hex,
    decode_identity_secret,
    durably_create_directory_all,
    finalize,
    generate_identity,
    prepare,
    publish_directory,
    read_ceremony,
    read_registration,
    read_trusted_genesis,
    read_validated_registrations,
    validate_bundle,
    write_new_file,
};

const IDENTITY_DIRECTORY: &str = "identity";
const REGISTRATIONS_DIRECTORY: &str = "registrations";
const CEREMONY_DIRECTORY: &str = "ceremony";
const DEALINGS_DIRECTORY: &str = "dealings";
const PUBLIC_DEALINGS_DIRECTORY: &str = "public-dealings";
const ACCEPTANCE_DIRECTORY: &str = "acceptance";
const PUBLIC_ACCEPTANCES_DIRECTORY: &str = "public-acceptances";
const BOARD_DIRECTORY: &str = "board";
const CEREMONY_WAIT_TIMEOUT: Duration = Duration::from_hours(24);
/// Inputs for the shared storage key DKG board.
#[derive(clap::Args)]
pub(super) struct DkgBoardServeOptions {
    /// Durable directory for the Iroh endpoint, document, and common ceremony files.
    #[arg(long, value_name = "DIR")]
    data_directory: PathBuf,

    /// Trusted genesis block for the network.
    #[arg(long, value_name = "FILE")]
    genesis: PathBuf,

    /// Number of shares needed to decrypt a private record.
    #[arg(long, value_name = "NUM")]
    threshold: NonZeroUsize,

    /// Hex-encoded 32-byte storage-key epoch.
    #[arg(long, value_name = "HEX")]
    epoch: String,

    /// New private directory that receives one board ticket per genesis validator.
    #[arg(long, value_name = "DIR")]
    ticket_directory: PathBuf,
}

/// Inputs for one validator's automatic storage key DKG ceremony runner.
#[derive(clap::Args)]
pub(super) struct DkgRunOptions {
    /// Private file containing the read and upload board ticket.
    #[arg(long, value_name = "FILE")]
    board_file: PathBuf,

    /// Trusted genesis block for the network.
    #[arg(long, value_name = "FILE")]
    genesis: PathBuf,

    /// Expected number of shares needed to decrypt a private record.
    #[arg(long, value_name = "NUM")]
    threshold: NonZeroUsize,

    /// Expected hex-encoded 32-byte storage-key epoch.
    #[arg(long, value_name = "HEX")]
    epoch: String,

    /// Validator signing key committed by genesis.
    #[command(flatten)]
    signing_key: ValidatorSigningKey,

    /// Durable directory for private ceremony state and the local Iroh endpoint.
    #[arg(long, value_name = "DIR")]
    work_directory: PathBuf,

    /// New directory that receives the final storage-key bundle.
    #[arg(long, value_name = "DIR")]
    output_directory: PathBuf,
}

/// Runs one validator through every DKG phase.
pub(super) async fn run_validator(options: DkgRunOptions) -> anyhow::Result<()> {
    let board = fs_err::read_to_string(&options.board_file)
        .with_context(|| {
            format!("failed to read storage key DKG board ticket {}", options.board_file.display())
        })?
        .trim()
        .to_owned();
    ensure!(!board.is_empty(), "storage key DKG board ticket must not be empty");
    let board = board.parse::<BoardTicket>().context("invalid storage key DKG board ticket")?;
    let signer = options.signing_key.into_signer().await?;
    run_validator_with_ticket::<SecpSecqBackend>(
        board,
        &options.genesis,
        &signer,
        options.threshold.get(),
        &options.epoch,
        &options.work_directory,
        &options.output_directory,
        CEREMONY_WAIT_TIMEOUT,
    )
    .await
}

pub(super) async fn serve_board(options: DkgBoardServeOptions) -> anyhow::Result<()> {
    let genesis = read_trusted_genesis(&options.genesis)?;
    let participant_count = genesis.inner().header().validator_config().keys().len();
    let (board, tickets) =
        CoordinatorBoard::create(&options.data_directory, participant_count).await?;
    publish_directory(&options.ticket_directory, |temporary| {
        for ticket in &tickets {
            write_new_file(
                &temporary.join(format!("participant-{}.ticket", ticket.participant())),
                ticket.to_string().as_bytes(),
                true,
            )?;
        }
        Ok(())
    })?;
    println!(
        "storage key DKG board tickets written to {}",
        options.ticket_directory.display()
    );

    let result = async {
        coordinate_common_files(
            &board,
            &options.data_directory,
            &options.genesis,
            options.threshold.get(),
            &options.epoch,
            CEREMONY_WAIT_TIMEOUT,
        )
        .await?;
        println!("storage key DKG board is ready. Press Ctrl-C to stop it.");
        tokio::signal::ctrl_c().await.context("failed to wait for Ctrl-C")
    }
    .await;
    let shutdown = board.shutdown().await;
    result.and(shutdown)
}

/// Waits for signed registrations, prepares the ceremony, and publishes its common files.
pub(super) async fn coordinate_common_files(
    board: &CoordinatorBoard,
    data_directory: &Path,
    genesis_path: &Path,
    threshold: usize,
    epoch: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let genesis = read_trusted_genesis(genesis_path)?;
    let validator_keys = genesis.inner().header().validator_config().keys();
    ensure!(
        threshold > 0 && threshold <= validator_keys.len(),
        "threshold must be between 1 and {}",
        validator_keys.len(),
    );
    decode_fixed_hex::<32>(epoch, "storage-key epoch")?;

    let ceremony_directory = data_directory.join(CEREMONY_DIRECTORY);
    if !ceremony_directory.exists() {
        let registrations = wait_for_registrations(board.reader(), validator_keys, timeout).await?;
        let registration_directory = data_directory.join(REGISTRATIONS_DIRECTORY);
        materialize_or_compare(&registration_directory, &registrations)?;
        let paths = registrations
            .iter()
            .map(|(name, _)| registration_directory.join(name))
            .collect::<Vec<_>>();
        prepare(genesis_path, threshold, epoch, &paths, &ceremony_directory)?;
    }

    let ceremony = read_ceremony(genesis_path, &ceremony_directory)?;
    ensure!(
        ceremony.manifest.threshold == threshold,
        "board threshold changed after creation"
    );
    ensure!(ceremony.manifest.epoch == epoch, "board epoch changed after creation");
    publish_common_file(board, CommonArtifact::Manifest, &ceremony_directory.join(MANIFEST_FILE))
        .await?;
    publish_common_file(
        board,
        CommonArtifact::DecryptionConfig,
        &ceremony_directory.join(DECRYPTION_CONFIG_FILE),
    )
    .await?;
    publish_common_file(
        board,
        CommonArtifact::ContextConfig,
        &ceremony_directory.join(CONTEXT_CONFIG_FILE),
    )
    .await?;
    Ok(())
}

async fn wait_for_registrations(
    board: &BoardReader,
    validator_keys: &[PublicKey],
    timeout: Duration,
) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let mut files = Vec::with_capacity(validator_keys.len());
    for (position, validator_key) in validator_keys.iter().enumerate() {
        let participant = participant_at(position)?;
        let bytes = board
            .wait_unique(&ArtifactSlot::Registration(participant.get()), timeout)
            .await?;
        let registration: Registration = toml::from_slice(&bytes).with_context(|| {
            format!("invalid registration for participant {}", participant.get())
        })?;
        ensure!(
            registration.validator_public_key == hex::encode(validator_key.to_bytes()),
            "registration slot {} belongs to another genesis validator",
            participant.get(),
        );
        files.push((format!("registration-{}.toml", participant.get()), bytes));
    }
    Ok(files)
}

/// Runs the restartable validator state machine over one board.
#[expect(
    clippy::too_many_arguments,
    reason = "the inputs separate ceremony policy from durable paths"
)]
pub(super) async fn run_validator_with_ticket<B>(
    ticket: BoardTicket,
    genesis_path: &Path,
    signer: &ValidatorSigner,
    threshold: usize,
    epoch: &str,
    work_directory: &Path,
    output_directory: &Path,
    timeout: Duration,
) -> anyhow::Result<()>
where
    B: EvrfProofBackend<StorageGroup>,
{
    durably_create_directory_all(work_directory).with_context(|| {
        format!("failed to create DKG work directory {}", work_directory.display())
    })?;
    let genesis = read_trusted_genesis(genesis_path)?;
    let validator_keys = genesis.inner().header().validator_config().keys();
    let participant_count = validator_keys.len();
    ensure!(
        threshold > 0 && threshold <= participant_count,
        "threshold must be between 1 and {participant_count}",
    );
    decode_fixed_hex::<32>(epoch, "storage-key epoch")?;
    let participant = prepare_local_identity(genesis_path, epoch, signer, work_directory).await?;
    ensure!(
        ticket.participant() == participant.get(),
        "storage key DKG board ticket belongs to participant {}, but the signing key belongs to participant {}",
        ticket.participant(),
        participant.get(),
    );
    let board_directory = work_directory.join(BOARD_DIRECTORY);
    let board = ParticipantBoard::join(&board_directory, ticket, participant_count).await?;
    let result = run_validator_on_board::<B>(
        &board,
        genesis_path,
        signer,
        participant,
        threshold,
        epoch,
        work_directory,
        output_directory,
        timeout,
    )
    .await;
    let shutdown = board.shutdown().await;
    result.and(shutdown)
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the inputs and linear body mirror the ceremony policy and phase order"
)]
pub(super) async fn run_validator_on_board<B>(
    board: &ParticipantBoard,
    genesis_path: &Path,
    signer: &ValidatorSigner,
    participant: ParticipantIndex,
    threshold: usize,
    epoch: &str,
    work_directory: &Path,
    output_directory: &Path,
    timeout: Duration,
) -> anyhow::Result<()>
where
    B: EvrfProofBackend<StorageGroup>,
{
    let identity_directory = work_directory.join(IDENTITY_DIRECTORY);
    publish_participant_file(
        board,
        ParticipantArtifact::Registration,
        &identity_directory.join(REGISTRATION_FILE),
    )
    .await?;

    let genesis = read_trusted_genesis(genesis_path)?;
    let registrations = wait_for_registrations(
        board.reader(),
        genesis.inner().header().validator_config().keys(),
        timeout,
    )
    .await?;
    let registration_directory = work_directory.join(REGISTRATIONS_DIRECTORY);
    materialize_or_compare(&registration_directory, &registrations)?;
    let registration_paths = registrations
        .iter()
        .map(|(name, _)| registration_directory.join(name))
        .collect::<Vec<_>>();
    let ceremony_directory = work_directory.join(CEREMONY_DIRECTORY);
    if !ceremony_directory.exists() {
        prepare(genesis_path, threshold, epoch, &registration_paths, &ceremony_directory)?;
    }
    let common = vec![
        (
            MANIFEST_FILE.to_owned(),
            board.reader().wait_unique(&ArtifactSlot::Manifest, timeout).await?,
        ),
        (
            DECRYPTION_CONFIG_FILE.to_owned(),
            board.reader().wait_unique(&ArtifactSlot::DecryptionConfig, timeout).await?,
        ),
        (
            CONTEXT_CONFIG_FILE.to_owned(),
            board.reader().wait_unique(&ArtifactSlot::ContextConfig, timeout).await?,
        ),
    ];
    materialize_or_compare(&ceremony_directory, &common)?;
    let ceremony = read_ceremony(genesis_path, &ceremony_directory)?;
    ensure!(
        ceremony.manifest.threshold == threshold,
        "board threshold does not match the validator's expected threshold"
    );
    ensure!(
        ceremony.manifest.epoch == epoch,
        "board epoch does not match the validator's expected epoch"
    );
    ensure!(
        ceremony.manifest.participants[participant.get() as usize - 1].validator_public_key
            == hex::encode(signer.public_key().to_bytes()),
        "validator signing key has the wrong ceremony participant index",
    );

    let dealings_directory = work_directory.join(DEALINGS_DIRECTORY);
    if !dealings_directory.exists() {
        deal::<B>(
            genesis_path,
            &ceremony_directory,
            &identity_directory.join(IDENTITY_SECRET_FILE),
            &dealings_directory,
            &mut OsRng,
        )?;
    }
    publish_participant_file(
        board,
        ParticipantArtifact::DecryptionDealing,
        &dealings_directory.join(DECRYPTION_DEALING_FILE),
    )
    .await?;
    publish_participant_file(
        board,
        ParticipantArtifact::ContextDealing,
        &dealings_directory.join(CONTEXT_DEALING_FILE),
    )
    .await?;

    let participant_count = ceremony.manifest.participants.len();
    let public_dealings_directory = work_directory.join(PUBLIC_DEALINGS_DIRECTORY);
    let public_dealings = wait_for_dealings(board.reader(), participant_count, timeout).await?;
    materialize_or_compare(&public_dealings_directory, &public_dealings)?;
    let decryption_dealings = participant_files(
        &public_dealings_directory,
        "decryption-dealing",
        "wire",
        participant_count,
    )?;
    let context_dealings = participant_files(
        &public_dealings_directory,
        "context-dealing",
        "wire",
        participant_count,
    )?;

    let acceptance_directory = work_directory.join(ACCEPTANCE_DIRECTORY);
    if !acceptance_directory.exists() {
        accept_transcript::<B>(
            genesis_path,
            &ceremony_directory,
            signer,
            &decryption_dealings,
            &context_dealings,
            &acceptance_directory,
        )
        .await?;
    }
    publish_participant_file(
        board,
        ParticipantArtifact::TranscriptAcceptance,
        &acceptance_directory.join(TRANSCRIPT_ACCEPTANCE_FILE),
    )
    .await?;

    let acceptances = wait_for_acceptances(board.reader(), participant_count, timeout).await?;
    let public_acceptances_directory = work_directory.join(PUBLIC_ACCEPTANCES_DIRECTORY);
    materialize_or_compare(&public_acceptances_directory, &acceptances)?;
    let transcript_path = acceptance_directory.join(TRANSCRIPT_FILE);
    let transcript_acceptances = participant_files(
        &public_acceptances_directory,
        "transcript-acceptance",
        "toml",
        participant_count,
    )?;

    if !output_directory.exists() {
        finalize::<B>(
            genesis_path,
            &ceremony_directory,
            &identity_directory.join(IDENTITY_SECRET_FILE),
            &dealings_directory.join(PRIVATE_STATE_FILE),
            &decryption_dealings,
            &context_dealings,
            &transcript_path,
            &transcript_acceptances,
            output_directory,
        )?;
    }
    validate_bundle(
        genesis_path,
        &ceremony_directory,
        &hex::encode(signer.public_key().to_bytes()),
        output_directory,
    )?;

    println!("storage key DKG completed for participant {}.", participant.get());
    Ok(())
}

pub(super) async fn prepare_local_identity(
    genesis_path: &Path,
    epoch: &str,
    signer: &ValidatorSigner,
    work_directory: &Path,
) -> anyhow::Result<ParticipantIndex> {
    let validator_key = signer.public_key();
    let participant = participant_for_validator(genesis_path, &validator_key)?;
    let identity_directory = work_directory.join(IDENTITY_DIRECTORY);
    if !identity_directory.exists() {
        generate_identity(genesis_path, epoch, signer, &identity_directory).await?;
    }
    validate_local_identity(genesis_path, epoch, &validator_key, &identity_directory)?;
    Ok(participant)
}

fn participant_for_validator(
    genesis_path: &Path,
    validator_key: &PublicKey,
) -> anyhow::Result<ParticipantIndex> {
    let genesis = read_trusted_genesis(genesis_path)?;
    let position = genesis
        .inner()
        .header()
        .validator_config()
        .keys()
        .iter()
        .position(|key| key == validator_key)
        .context("validator signing key is not committed by genesis")?;
    participant_at(position)
}

fn participant_at(position: usize) -> anyhow::Result<ParticipantIndex> {
    ParticipantIndex::new(u32::try_from(position + 1).context("too many DKG participants")?)
        .map_err(Into::into)
}

fn validate_local_identity(
    genesis_path: &Path,
    epoch: &str,
    validator_key: &PublicKey,
    identity_directory: &Path,
) -> anyhow::Result<()> {
    let registration_path = identity_directory.join(REGISTRATION_FILE);
    let registration = read_registration(&registration_path)?;
    ensure!(
        registration.validator_public_key == hex::encode(validator_key.to_bytes()),
        "stored DKG identity belongs to another validator",
    );
    let genesis = read_trusted_genesis(genesis_path)?;
    let expected_epoch = decode_fixed_hex::<32>(epoch, "storage-key epoch")?;
    read_validated_registrations(
        &[registration_path],
        genesis.inner().header().commitment(),
        &expected_epoch,
    )?;
    let secret = Zeroizing::new(fs_err::read(identity_directory.join(IDENTITY_SECRET_FILE))?);
    let secret = decode_identity_secret(&secret)?;
    ensure!(
        hex::encode(StorageGroup::encode_element(&StorageGroup::mul_generator(&secret)))
            == registration.dkg_identity_public_key,
        "stored DKG identity secret does not match its registration",
    );
    Ok(())
}

async fn wait_for_dealings(
    board: &BoardReader,
    participant_count: usize,
    timeout: Duration,
) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let mut files = Vec::with_capacity(participant_count * 2);
    for position in 0..participant_count {
        let participant = participant_at(position)?;
        files.push((
            format!("decryption-dealing-{}.wire", participant.get()),
            board
                .wait_unique(&ArtifactSlot::DecryptionDealing(participant.get()), timeout)
                .await?,
        ));
        files.push((
            format!("context-dealing-{}.wire", participant.get()),
            board
                .wait_unique(&ArtifactSlot::ContextDealing(participant.get()), timeout)
                .await?,
        ));
    }
    Ok(files)
}

async fn wait_for_acceptances(
    board: &BoardReader,
    participant_count: usize,
    timeout: Duration,
) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let mut acceptances = Vec::with_capacity(participant_count);
    for position in 0..participant_count {
        let participant = participant_at(position)?;
        acceptances.push((
            format!("transcript-acceptance-{}.toml", participant.get()),
            board
                .wait_unique(&ArtifactSlot::TranscriptAcceptance(participant.get()), timeout)
                .await?,
        ));
    }
    Ok(acceptances)
}

async fn publish_common_file(
    board: &CoordinatorBoard,
    artifact: CommonArtifact,
    path: &Path,
) -> anyhow::Result<()> {
    let bytes = fs_err::read(path)
        .with_context(|| format!("failed to read ceremony artifact {}", path.display()))?;
    board.publish(artifact, &bytes).await
}

async fn publish_participant_file(
    board: &ParticipantBoard,
    artifact: ParticipantArtifact,
    path: &Path,
) -> anyhow::Result<()> {
    let bytes = fs_err::read(path)
        .with_context(|| format!("failed to read ceremony artifact {}", path.display()))?;
    board.publish(artifact, &bytes).await?;
    Ok(())
}

fn materialize_or_compare(directory: &Path, files: &[(String, Vec<u8>)]) -> anyhow::Result<()> {
    if directory.exists() {
        for (name, expected) in files {
            let path = directory.join(name);
            let actual = fs_err::read(&path).with_context(|| {
                format!("failed to read cached board artifact {}", path.display())
            })?;
            ensure!(actual == *expected, "cached board artifact {} changed", path.display());
        }
        return Ok(());
    }
    publish_directory(directory, |temporary| {
        for (name, bytes) in files {
            write_new_file(&temporary.join(name), bytes, false)?;
        }
        Ok(())
    })
}

fn participant_files(
    directory: &Path,
    stem: &str,
    extension: &str,
    participant_count: usize,
) -> anyhow::Result<Vec<PathBuf>> {
    (0..participant_count)
        .map(|position| {
            Ok(directory.join(format!("{stem}-{}.{}", participant_at(position)?.get(), extension)))
        })
        .collect()
}
