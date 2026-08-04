use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, ensure};
use golden_core::{EvrfProofBackend, ParticipantIndex};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_validator::ValidatorSigner;

use super::board::{ArtifactSlot, BoardNode};
use super::{
    CONTEXT_CONFIG_FILE,
    CONTEXT_DEALING_FILE,
    DECRYPTION_CONFIG_FILE,
    DECRYPTION_DEALING_FILE,
    Deserialize,
    Digest,
    EPOCH_FILE,
    GoldenGroup,
    IDENTITY_SECRET_FILE,
    MANIFEST_FILE,
    OsRng,
    PRIVATE_STATE_FILE,
    PUBLIC_KEY_SET_FILE,
    REGISTRATION_FILE,
    Registration,
    Rpo256,
    SETUP_CONTEXT_FILE,
    SecpSecqBackend,
    Serializable,
    Serialize,
    Sha256,
    StorageGroup,
    TRANSCRIPT_ACCEPTANCE_FILE,
    TRANSCRIPT_FILE,
    ValidatorSigningKey,
    WireMessage,
    Word,
    Zeroizing,
    accept_transcript,
    deal,
    decode_fixed_hex,
    decode_identity_secret,
    decode_validator_public_key,
    decode_validator_signature,
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
const CEREMONY_DIRECTORY: &str = "ceremony";
const DEALINGS_DIRECTORY: &str = "dealings";
const PUBLIC_DEALINGS_DIRECTORY: &str = "public-dealings";
const ACCEPTANCE_DIRECTORY: &str = "acceptance";
const PUBLIC_ACCEPTANCES_DIRECTORY: &str = "public-acceptances";
const BOARD_DIRECTORY: &str = "board";
const CEREMONY_WAIT_TIMEOUT: Duration = Duration::from_hours(24);
const PUBLIC_OUTPUT_DIGEST_DOMAIN: &[u8] = b"miden-golden-dkg-public-output-v1";
const FINAL_CONFIRMATION_VERSION: &str = "miden-golden-dkg-final-confirmation-v1";
const FINAL_CONFIRMATION_SIGNATURE_DOMAIN: &[u8] =
    b"miden-golden-dkg-final-confirmation-signature-v1";

#[derive(Deserialize, Serialize)]
struct FinalConfirmation {
    version: String,
    validator_public_key: String,
    public_output_sha256: String,
    validator_signature: String,
}

/// Inputs for the shared Golden DKG board.
#[derive(clap::Args)]
pub(super) struct GoldenDkgBoardServeOptions {
    /// Durable directory for the Iroh endpoint, document, and common ceremony files.
    #[arg(long, value_name = "DIR")]
    data_directory: PathBuf,

    /// Trusted genesis block for the network.
    #[arg(long, value_name = "FILE")]
    genesis: PathBuf,

    /// Number of shares needed to decrypt a private record.
    #[arg(long, value_name = "NUM")]
    threshold: usize,

    /// Hex-encoded 32-byte storage-key epoch.
    #[arg(long, value_name = "HEX")]
    epoch: String,

    /// New private file that receives the board ticket for automation.
    #[arg(long, value_name = "FILE")]
    ticket_output: Option<PathBuf>,
}

/// Inputs for one validator's automatic Golden DKG ceremony runner.
#[derive(clap::Args)]
pub(super) struct GoldenDkgRunOptions {
    /// Read and upload ticket printed by `golden-dkg board`.
    #[arg(long, value_name = "BOARD_TICKET", required_unless_present = "board_file")]
    board: Option<String>,

    /// Private file containing the read and upload board ticket.
    #[arg(long, value_name = "FILE", conflicts_with = "board")]
    board_file: Option<PathBuf>,

    /// Trusted genesis block for the network.
    #[arg(long, value_name = "FILE")]
    genesis: PathBuf,

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
pub(super) async fn run_validator(options: GoldenDkgRunOptions) -> anyhow::Result<()> {
    let board = if let Some(ticket) = options.board {
        ticket
    } else {
        let path = options.board_file.context("a board ticket or board ticket file is required")?;
        fs_err::read_to_string(&path)
            .with_context(|| format!("failed to read Golden DKG board ticket {}", path.display()))?
            .trim()
            .to_owned()
    };
    ensure!(!board.is_empty(), "Golden DKG board ticket must not be empty");
    let signer = options.signing_key.into_signer().await?;
    run_validator_with_network::<SecpSecqBackend>(
        &board,
        &options.genesis,
        &signer,
        &options.work_directory,
        &options.output_directory,
        true,
        CEREMONY_WAIT_TIMEOUT,
    )
    .await
}

pub(super) async fn serve_board(options: GoldenDkgBoardServeOptions) -> anyhow::Result<()> {
    let genesis = read_trusted_genesis(&options.genesis)?;
    let participant_count = genesis.inner().header().validator_keys().as_keys().len();
    let (board, ticket) = BoardNode::create(&options.data_directory, participant_count).await?;
    if let Some(path) = &options.ticket_output {
        write_new_file(path, ticket.to_string().as_bytes(), true)?;
        println!("Golden DKG board ticket written to {}", path.display());
    } else {
        println!("Golden DKG board ticket:\n{ticket}");
    }

    let result = async {
        coordinate_common_files(
            &board,
            &options.data_directory,
            &options.genesis,
            options.threshold,
            &options.epoch,
            CEREMONY_WAIT_TIMEOUT,
        )
        .await?;
        println!("Golden DKG board is ready. Press Ctrl-C to stop it.");
        tokio::signal::ctrl_c().await.context("failed to wait for Ctrl-C")
    }
    .await;
    let shutdown = board.shutdown().await;
    result.and(shutdown)
}

/// Waits for signed registrations, prepares the ceremony, and publishes its common files.
pub(super) async fn coordinate_common_files(
    board: &BoardNode,
    data_directory: &Path,
    genesis_path: &Path,
    threshold: usize,
    epoch: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let genesis = read_trusted_genesis(genesis_path)?;
    let validator_keys = genesis.inner().header().validator_keys().as_keys();
    ensure!(
        threshold > 0 && threshold <= validator_keys.len(),
        "threshold must be between 1 and {}",
        validator_keys.len(),
    );
    decode_fixed_hex::<32>(epoch, "storage-key epoch")?;

    let ceremony_directory = data_directory.join(CEREMONY_DIRECTORY);
    if !ceremony_directory.exists() {
        let registrations = wait_for_registrations(board, validator_keys, timeout).await?;
        let registration_directory = data_directory.join("registrations");
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
    publish_named_file(board, &ArtifactSlot::Manifest, &ceremony_directory.join(MANIFEST_FILE))
        .await?;
    publish_named_file(
        board,
        &ArtifactSlot::DecryptionConfig,
        &ceremony_directory.join(DECRYPTION_CONFIG_FILE),
    )
    .await?;
    publish_named_file(
        board,
        &ArtifactSlot::ContextConfig,
        &ceremony_directory.join(CONTEXT_CONFIG_FILE),
    )
    .await?;
    Ok(())
}

async fn wait_for_registrations(
    board: &BoardNode,
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
pub(super) async fn run_validator_with_network<B>(
    ticket: &str,
    genesis_path: &Path,
    signer: &ValidatorSigner,
    work_directory: &Path,
    output_directory: &Path,
    use_network_services: bool,
    timeout: Duration,
) -> anyhow::Result<()>
where
    B: EvrfProofBackend<StorageGroup>,
    B::Proof: WireMessage,
{
    fs_err::create_dir_all(work_directory).with_context(|| {
        format!("failed to create DKG work directory {}", work_directory.display())
    })?;
    let genesis = read_trusted_genesis(genesis_path)?;
    let participant_count = genesis.inner().header().validator_keys().as_keys().len();
    let participant = prepare_local_identity(genesis_path, signer, work_directory).await?;
    let board_directory = work_directory.join(BOARD_DIRECTORY);
    let board = if use_network_services {
        BoardNode::join(&board_directory, ticket, participant_count).await?
    } else {
        BoardNode::join_with_network(&board_directory, ticket, participant_count, false).await?
    };
    let result = run_validator_on_board::<B>(
        &board,
        genesis_path,
        signer,
        participant,
        work_directory,
        output_directory,
        timeout,
    )
    .await;
    let shutdown = board.shutdown().await;
    result.and(shutdown)
}

#[expect(
    clippy::too_many_lines,
    reason = "the linear body mirrors the ceremony phase order"
)]
async fn run_validator_on_board<B>(
    board: &BoardNode,
    genesis_path: &Path,
    signer: &ValidatorSigner,
    participant: ParticipantIndex,
    work_directory: &Path,
    output_directory: &Path,
    timeout: Duration,
) -> anyhow::Result<()>
where
    B: EvrfProofBackend<StorageGroup>,
    B::Proof: WireMessage,
{
    let identity_directory = work_directory.join(IDENTITY_DIRECTORY);
    publish_named_file(
        board,
        &ArtifactSlot::Registration(participant.get()),
        &identity_directory.join(REGISTRATION_FILE),
    )
    .await?;

    let ceremony_directory = work_directory.join(CEREMONY_DIRECTORY);
    let common = vec![
        (
            MANIFEST_FILE.to_owned(),
            board.wait_unique(&ArtifactSlot::Manifest, timeout).await?,
        ),
        (
            DECRYPTION_CONFIG_FILE.to_owned(),
            board.wait_unique(&ArtifactSlot::DecryptionConfig, timeout).await?,
        ),
        (
            CONTEXT_CONFIG_FILE.to_owned(),
            board.wait_unique(&ArtifactSlot::ContextConfig, timeout).await?,
        ),
    ];
    materialize_or_compare(&ceremony_directory, &common)?;
    let ceremony = read_ceremony(genesis_path, &ceremony_directory)?;
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
    publish_named_file(
        board,
        &ArtifactSlot::DecryptionDealing(participant.get()),
        &dealings_directory.join(DECRYPTION_DEALING_FILE),
    )
    .await?;
    publish_named_file(
        board,
        &ArtifactSlot::ContextDealing(participant.get()),
        &dealings_directory.join(CONTEXT_DEALING_FILE),
    )
    .await?;

    let participant_count = ceremony.manifest.participants.len();
    let public_dealings_directory = work_directory.join(PUBLIC_DEALINGS_DIRECTORY);
    let public_dealings = wait_for_dealings(board, participant_count, timeout).await?;
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
    publish_named_file(
        board,
        &ArtifactSlot::Transcript(participant.get()),
        &acceptance_directory.join(TRANSCRIPT_FILE),
    )
    .await?;
    publish_named_file(
        board,
        &ArtifactSlot::TranscriptAcceptance(participant.get()),
        &acceptance_directory.join(TRANSCRIPT_ACCEPTANCE_FILE),
    )
    .await?;

    let (transcript, acceptances) = wait_for_acceptances(board, participant_count, timeout).await?;
    let public_acceptances_directory = work_directory.join(PUBLIC_ACCEPTANCES_DIRECTORY);
    let mut acceptance_files = vec![(TRANSCRIPT_FILE.to_owned(), transcript)];
    acceptance_files.extend(acceptances);
    materialize_or_compare(&public_acceptances_directory, &acceptance_files)?;
    let transcript_path = public_acceptances_directory.join(TRANSCRIPT_FILE);
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

    let digest = public_output_digest(output_directory)?;
    let confirmation = sign_final_confirmation(signer, ceremony.genesis_commitment, digest).await?;
    board
        .publish(&ArtifactSlot::FinalConfirmation(participant.get()), &confirmation)
        .await?;
    for position in 0..participant_count {
        let other = participant_at(position)?;
        let other_confirmation = board
            .wait_unique(&ArtifactSlot::FinalConfirmation(other.get()), timeout)
            .await?;
        validate_final_confirmation(
            &other_confirmation,
            &ceremony.manifest.participants[position].validator_public_key,
            ceremony.genesis_commitment,
            digest,
        )?;
    }
    println!("Golden DKG completed for participant {}.", participant.get());
    Ok(())
}

pub(super) async fn prepare_local_identity(
    genesis_path: &Path,
    signer: &ValidatorSigner,
    work_directory: &Path,
) -> anyhow::Result<ParticipantIndex> {
    let validator_key = signer.public_key();
    let participant = participant_for_validator(genesis_path, &validator_key)?;
    let identity_directory = work_directory.join(IDENTITY_DIRECTORY);
    if !identity_directory.exists() {
        generate_identity(genesis_path, signer, &identity_directory).await?;
    }
    validate_local_identity(genesis_path, &validator_key, &identity_directory)?;
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
        .validator_keys()
        .as_keys()
        .iter()
        .position(|key| key == validator_key)
        .context("validator signing key is not committed by genesis")?;
    participant_at(position)
}

fn participant_at(position: usize) -> anyhow::Result<ParticipantIndex> {
    ParticipantIndex::new(u32::try_from(position + 1).context("too many Golden participants")?)
        .map_err(Into::into)
}

fn validate_local_identity(
    genesis_path: &Path,
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
    read_validated_registrations(&[registration_path], genesis.inner().header().commitment())?;
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
    board: &BoardNode,
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
    board: &BoardNode,
    participant_count: usize,
    timeout: Duration,
) -> anyhow::Result<(Vec<u8>, Vec<(String, Vec<u8>)>)> {
    let mut transcript = None;
    let mut acceptances = Vec::with_capacity(participant_count);
    for position in 0..participant_count {
        let participant = participant_at(position)?;
        let candidate =
            board.wait_unique(&ArtifactSlot::Transcript(participant.get()), timeout).await?;
        if let Some(expected) = &transcript {
            ensure!(candidate == *expected, "validators accepted different DKG transcripts");
        } else {
            transcript = Some(candidate);
        }
        acceptances.push((
            format!("transcript-acceptance-{}.toml", participant.get()),
            board
                .wait_unique(&ArtifactSlot::TranscriptAcceptance(participant.get()), timeout)
                .await?,
        ));
    }
    Ok((transcript.context("ceremony has no participants")?, acceptances))
}

async fn publish_named_file(
    board: &BoardNode,
    slot: &ArtifactSlot,
    path: &Path,
) -> anyhow::Result<()> {
    let bytes = fs_err::read(path)
        .with_context(|| format!("failed to read ceremony artifact {}", path.display()))?;
    board.publish(slot, &bytes).await?;
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

fn public_output_digest(bundle_directory: &Path) -> anyhow::Result<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(PUBLIC_OUTPUT_DIGEST_DOMAIN);
    for name in [EPOCH_FILE, SETUP_CONTEXT_FILE, PUBLIC_KEY_SET_FILE] {
        let bytes = fs_err::read(bundle_directory.join(name))?;
        digest.update(u64::try_from(bytes.len())?.to_be_bytes());
        digest.update(bytes);
    }
    Ok(digest.finalize().into())
}

async fn sign_final_confirmation(
    signer: &ValidatorSigner,
    genesis_commitment: Word,
    public_output_sha256: [u8; 32],
) -> anyhow::Result<Vec<u8>> {
    let validator_public_key = signer.public_key();
    let signature = signer
        .sign_commitment(final_confirmation_commitment(genesis_commitment, public_output_sha256))
        .await
        .context("failed to sign Golden final confirmation")?;
    let confirmation = FinalConfirmation {
        version: FINAL_CONFIRMATION_VERSION.to_owned(),
        validator_public_key: hex::encode(validator_public_key.to_bytes()),
        public_output_sha256: hex::encode(public_output_sha256),
        validator_signature: hex::encode(signature.to_bytes()),
    };
    toml::to_string_pretty(&confirmation)
        .context("failed to encode Golden final confirmation")
        .map(String::into_bytes)
}

fn validate_final_confirmation(
    bytes: &[u8],
    expected_validator_public_key: &str,
    genesis_commitment: Word,
    expected_public_output_sha256: [u8; 32],
) -> anyhow::Result<()> {
    let confirmation: FinalConfirmation =
        toml::from_slice(bytes).context("invalid Golden final confirmation")?;
    ensure!(
        confirmation.version == FINAL_CONFIRMATION_VERSION,
        "unsupported Golden final confirmation version"
    );
    ensure!(
        confirmation.validator_public_key == expected_validator_public_key,
        "Golden final confirmation belongs to another validator"
    );
    ensure!(
        confirmation.public_output_sha256 == hex::encode(expected_public_output_sha256),
        "validators produced different Golden public outputs"
    );
    let validator_public_key = decode_validator_public_key(&confirmation.validator_public_key)?;
    let signature = decode_validator_signature(&confirmation.validator_signature)?;
    ensure!(
        signature.verify(
            final_confirmation_commitment(genesis_commitment, expected_public_output_sha256),
            &validator_public_key,
        ),
        "invalid Golden final confirmation signature"
    );
    Ok(())
}

fn final_confirmation_commitment(genesis_commitment: Word, public_output_sha256: [u8; 32]) -> Word {
    let mut bytes = Vec::with_capacity(
        FINAL_CONFIRMATION_SIGNATURE_DOMAIN.len()
            + Word::SERIALIZED_SIZE
            + public_output_sha256.len(),
    );
    bytes.extend_from_slice(FINAL_CONFIRMATION_SIGNATURE_DOMAIN);
    bytes.extend_from_slice(&genesis_commitment.to_bytes());
    bytes.extend_from_slice(&public_output_sha256);
    Rpo256::hash(&bytes)
}

#[cfg(test)]
mod tests;
