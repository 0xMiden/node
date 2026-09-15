use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, ensure};
use golden_core::wire::{from_wire_bytes as from_core_wire_bytes, to_wire_bytes};
use golden_core::{
    DealerMessage,
    DkgConfig,
    DkgDealing,
    EvrfProofBackend,
    GoldenGroup,
    GoldenScalar,
    ParticipantIndex,
    ParticipantRegistry,
    SessionId,
    Share,
    TranscriptBuilder,
    complete,
    create_dealing,
    create_dealing_with_secret,
    verify_dealing,
};
use golden_ehtdh1::wire::to_wire_bytes as to_ehtdh1_wire_bytes;
use golden_ehtdh1::{
    Ehtdh1Material,
    PublicKeySet,
    PublicShare,
    SetupContext,
    derive_context_session_id,
    material_from_dkg_outputs,
};
use golden_evrf::paper::secp_secq::SecpSecqBackend;
use golden_halo2curves::golden_group::Secp256k1GoldenGroup;
use miden_node_store::genesis::GenesisBlock;
use miden_node_utils::genesis::read_genesis_block;
use miden_protocol::Word;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::crypto::hash::rpo::Rpo256;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_validator::{EncodedGoldenOperatorKey, StorageKeyEpoch, ValidatorSigner};
use rand_core_06::{CryptoRngCore, OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::ValidatorSigningKey;

#[cfg(test)]
mod tests;

type StorageGroup = Secp256k1GoldenGroup;
type StorageScalar = <StorageGroup as GoldenGroup>::Scalar;
type StorageElement = <StorageGroup as GoldenGroup>::Element;
type PublicOutput = (StorageElement, BTreeMap<ParticipantIndex, StorageElement>);

const REGISTRATION_VERSION: &str = "miden-storage-key-dkg-registration-v2";
const MANIFEST_VERSION: &str = "miden-storage-key-dkg-manifest-v2";
const REGISTRATION_SIGNATURE_DOMAIN: &[u8] = b"miden-storage-key-dkg-registration-signature-v2";
const IDENTITY_PROOF_DOMAIN: &[u8] = b"miden-storage-key-dkg-identity-proof-v1";
const SETUP_BETA_DOMAIN: &[u8] = b"miden-storage-key-dkg-beta-v1";
const DECRYPTION_SESSION_DOMAIN: &[u8] = b"miden-storage-key-dkg-session-v1";
const IDENTITY_SECRET_MAGIC: &[u8] = b"miden-storage-key-dkg-identity-v1\0";
const IDENTITY_SECRET_FILE: &str = "identity-secret.wire";
const REGISTRATION_FILE: &str = "registration.toml";
const MANIFEST_FILE: &str = "manifest.toml";
const DECRYPTION_CONFIG_FILE: &str = "decryption-config.wire";
const CONTEXT_CONFIG_FILE: &str = "context-config.wire";
const DECRYPTION_DEALING_FILE: &str = "decryption-dealing.wire";
const CONTEXT_DEALING_FILE: &str = "context-dealing.wire";
const PRIVATE_STATE_FILE: &str = "private-state.wire";
const PRIVATE_STATE_MAGIC: &[u8] = b"miden-storage-key-dkg-local-state-v1\0";
const EPOCH_FILE: &str = "epoch.hex";
const SETUP_CONTEXT_FILE: &str = "setup-context.wire";
const PUBLIC_KEY_SET_FILE: &str = "public-key-set.wire";
const SECRET_SHARE_FILE: &str = "secret-share.wire";
const TRANSCRIPT_VERSION: &str = "miden-storage-key-dkg-transcript-v1";
const TRANSCRIPT_ACCEPTANCE_VERSION: &str = "miden-storage-key-dkg-transcript-acceptance-v1";
const TRANSCRIPT_SIGNATURE_DOMAIN: &[u8] = b"miden-storage-key-dkg-transcript-signature-v1";
const TRANSCRIPT_FILE: &str = "transcript.toml";
const TRANSCRIPT_ACCEPTANCE_FILE: &str = "transcript-acceptance.toml";
const TRANSCRIPT_ACCEPTANCES_FILE: &str = "transcript-acceptances.toml";

/// Inputs for one DKG ceremony command.
#[derive(clap::Args)]
pub struct DkgOptions {
    #[command(subcommand)]
    command: DkgCommand,
}

/// DKG ceremony commands.
#[derive(clap::Subcommand)]
enum DkgCommand {
    /// Generates this validator's DKG identity and public registration.
    Identity {
        /// Trusted genesis block for the network.
        #[arg(long, value_name = "FILE")]
        genesis: PathBuf,

        /// Hex-encoded 32-byte storage-key epoch.
        #[arg(long, value_name = "HEX")]
        epoch: String,

        /// Validator signing key committed by genesis.
        #[command(flatten)]
        signing_key: ValidatorSigningKey,

        /// New directory that receives the identity and registration files.
        #[arg(long, value_name = "DIR")]
        output_directory: PathBuf,
    },

    /// Builds the public configurations for both DKG rounds.
    Prepare {
        /// Trusted genesis block for the network.
        #[arg(long, value_name = "FILE")]
        genesis: PathBuf,

        /// Number of shares needed to decrypt a private record.
        #[arg(long, value_name = "NUM")]
        threshold: usize,

        /// Hex-encoded 32-byte storage-key epoch.
        #[arg(long, value_name = "HEX")]
        epoch: String,

        /// Public registration from one validator. Repeat once per genesis validator.
        #[arg(long, required = true, value_name = "FILE")]
        registration: Vec<PathBuf>,

        /// New directory that receives the manifest and public DKG configurations.
        #[arg(long, value_name = "DIR")]
        output_directory: PathBuf,
    },

    /// Creates this validator's public dealings and private local state.
    Deal {
        /// Trusted genesis block for the network.
        #[arg(long, value_name = "FILE")]
        genesis: PathBuf,

        /// Directory containing the shared ceremony manifest and configurations.
        #[arg(long, value_name = "DIR")]
        ceremony_directory: PathBuf,

        /// This validator's private DKG identity file.
        #[arg(long, value_name = "FILE")]
        identity_secret: PathBuf,

        /// New directory that receives public dealings and private local state.
        #[arg(long, value_name = "DIR")]
        output_directory: PathBuf,
    },

    /// Signs the common manifest and dealing transcript.
    Accept {
        /// Trusted genesis block for the network.
        #[arg(long, value_name = "FILE")]
        genesis: PathBuf,

        /// Directory containing the shared ceremony manifest and configurations.
        #[arg(long, value_name = "DIR")]
        ceremony_directory: PathBuf,

        /// Validator signing key committed by genesis.
        #[command(flatten)]
        signing_key: ValidatorSigningKey,

        /// Public decryption-round dealing. Repeat once per genesis validator.
        #[arg(long, required = true, value_name = "FILE")]
        decryption_dealing: Vec<PathBuf>,

        /// Public context-round dealing. Repeat once per genesis validator.
        #[arg(long, required = true, value_name = "FILE")]
        context_dealing: Vec<PathBuf>,

        /// New directory that receives the transcript and this validator's acceptance.
        #[arg(long, value_name = "DIR")]
        output_directory: PathBuf,
    },

    /// Completes both DKG rounds and writes this validator's startup bundle.
    Finalize {
        /// Trusted genesis block for the network.
        #[arg(long, value_name = "FILE")]
        genesis: PathBuf,

        /// Directory containing the shared ceremony manifest and configurations.
        #[arg(long, value_name = "DIR")]
        ceremony_directory: PathBuf,

        /// This validator's private DKG identity file.
        #[arg(long, value_name = "FILE")]
        identity_secret: PathBuf,

        /// Private state produced by this validator's `deal` command.
        #[arg(long, value_name = "FILE")]
        private_state: PathBuf,

        /// Public decryption-round dealing. Repeat once per genesis validator.
        #[arg(long, required = true, value_name = "FILE")]
        decryption_dealing: Vec<PathBuf>,

        /// Public context-round dealing. Repeat once per genesis validator.
        #[arg(long, required = true, value_name = "FILE")]
        context_dealing: Vec<PathBuf>,

        /// Canonical transcript accepted by every genesis validator.
        #[arg(long, value_name = "FILE")]
        transcript: PathBuf,

        /// Signed transcript acceptance. Repeat once per genesis validator.
        #[arg(long, required = true, value_name = "FILE")]
        transcript_acceptance: Vec<PathBuf>,

        /// New directory that receives this validator's startup bundle.
        #[arg(long, value_name = "DIR")]
        output_directory: PathBuf,
    },

    /// Checks one startup bundle against genesis and the ceremony manifest.
    Validate {
        /// Trusted genesis block for the network.
        #[arg(long, value_name = "FILE")]
        genesis: PathBuf,

        /// Directory containing the shared ceremony manifest and configurations.
        #[arg(long, value_name = "DIR")]
        ceremony_directory: PathBuf,

        /// Genesis validator public key that owns this bundle.
        #[arg(long, value_name = "HEX")]
        validator_public_key: String,

        /// Directory containing the final storage-key bundle.
        #[arg(long, value_name = "DIR")]
        bundle_directory: PathBuf,
    },

    /// Checks a committed local-development fixture against one participant index.
    ValidateFixture {
        /// Directory containing the four storage-key fixture files.
        #[arg(long, value_name = "DIR")]
        bundle_directory: PathBuf,

        /// DKG participant index that must own the secret share.
        #[arg(long, value_name = "NUM")]
        expected_participant: u32,
    },
}

#[derive(Debug, Deserialize, Serialize)]
struct Registration {
    version: String,
    genesis_commitment: String,
    epoch: String,
    validator_public_key: String,
    dkg_identity_public_key: String,
    identity_proof_commitment: String,
    identity_proof_response: String,
    validator_signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Manifest {
    version: String,
    genesis_commitment: String,
    threshold: usize,
    epoch: String,
    beta: String,
    decryption_session_id: String,
    context_session_id: String,
    decryption_config_sha256: String,
    context_config_sha256: String,
    participants: Vec<ManifestParticipant>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ManifestParticipant {
    participant_index: u32,
    validator_public_key: String,
    dkg_identity_public_key: String,
}

struct Ceremony {
    manifest: Manifest,
    manifest_sha256: [u8; 32],
    genesis_commitment: Word,
    decryption_config: DkgConfig<StorageGroup>,
    context_config: DkgConfig<StorageGroup>,
}

struct PrivateState {
    participant: ParticipantIndex,
    decryption_session_id: SessionId,
    context_session_id: SessionId,
    decryption_message_sha256: [u8; 32],
    context_message_sha256: [u8; 32],
    decryption_private_share: StorageScalar,
    context_private_share: StorageScalar,
}

#[derive(Debug, Deserialize, Serialize)]
struct CeremonyTranscript {
    version: String,
    manifest_sha256: String,
    decryption_transcript_root: String,
    context_transcript_root: String,
    public_key_set_sha256: String,
    decryption_dealings: Vec<TranscriptDealing>,
    context_dealings: Vec<TranscriptDealing>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct TranscriptDealing {
    participant_index: u32,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TranscriptAcceptance {
    version: String,
    validator_public_key: String,
    transcript_sha256: String,
    validator_signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct TranscriptAcceptances {
    acceptances: Vec<TranscriptAcceptance>,
}

struct DealingSet {
    messages: BTreeMap<ParticipantIndex, DealerMessage<StorageGroup>>,
    hashes: Vec<TranscriptDealing>,
}

/// Runs one DKG ceremony command.
pub async fn run(options: DkgOptions) -> anyhow::Result<()> {
    match options.command {
        DkgCommand::Identity {
            genesis,
            epoch,
            signing_key,
            output_directory,
        } => {
            let signer = signing_key.into_signer().await?;
            generate_identity(&genesis, &epoch, &signer, &output_directory).await
        },
        DkgCommand::Prepare {
            genesis,
            threshold,
            epoch,
            registration,
            output_directory,
        } => prepare(&genesis, threshold, &epoch, &registration, &output_directory),
        DkgCommand::Deal {
            genesis,
            ceremony_directory,
            identity_secret,
            output_directory,
        } => deal::<SecpSecqBackend>(
            &genesis,
            &ceremony_directory,
            &identity_secret,
            &output_directory,
            &mut OsRng,
        ),
        DkgCommand::Accept {
            genesis,
            ceremony_directory,
            signing_key,
            decryption_dealing,
            context_dealing,
            output_directory,
        } => {
            let signer = signing_key.into_signer().await?;
            accept_transcript::<SecpSecqBackend>(
                &genesis,
                &ceremony_directory,
                &signer,
                &decryption_dealing,
                &context_dealing,
                &output_directory,
            )
            .await
        },
        DkgCommand::Finalize {
            genesis,
            ceremony_directory,
            identity_secret,
            private_state,
            decryption_dealing,
            context_dealing,
            transcript,
            transcript_acceptance,
            output_directory,
        } => finalize::<SecpSecqBackend>(
            &genesis,
            &ceremony_directory,
            &identity_secret,
            &private_state,
            &decryption_dealing,
            &context_dealing,
            &transcript,
            &transcript_acceptance,
            &output_directory,
        ),
        DkgCommand::Validate {
            genesis,
            ceremony_directory,
            validator_public_key,
            bundle_directory,
        } => {
            validate_bundle(&genesis, &ceremony_directory, &validator_public_key, &bundle_directory)
        },
        DkgCommand::ValidateFixture { bundle_directory, expected_participant } => {
            validate_fixture_bundle(&bundle_directory, expected_participant)
        },
    }
}

/// Generates one validator's private DKG identity and public registration.
async fn generate_identity(
    genesis_path: &Path,
    epoch: &str,
    signer: &ValidatorSigner,
    output_directory: &Path,
) -> anyhow::Result<()> {
    let epoch = decode_fixed_hex::<32>(epoch, "storage-key epoch")?;
    let genesis = read_trusted_genesis(genesis_path)?;
    let genesis_commitment = genesis.inner().header().commitment();
    let validator_public_key = signer.public_key();
    ensure!(
        genesis
            .inner()
            .header()
            .validator_config()
            .keys()
            .contains(&validator_public_key),
        "validator signing key is not committed by genesis",
    );
    let identity_secret = StorageScalar::random(&mut OsRng);
    ensure!(!bool::from(identity_secret.is_zero()), "generated a zero DKG identity secret");
    let identity_public_key = StorageGroup::mul_generator(&identity_secret);
    let (proof_commitment, proof_response) = create_identity_proof(
        genesis_commitment,
        &epoch,
        &validator_public_key,
        &identity_secret,
        &mut OsRng,
    )?;
    let signature_commitment = registration_signature_commitment(
        genesis_commitment,
        &epoch,
        &validator_public_key,
        &identity_public_key,
        &proof_commitment,
        &proof_response,
    );
    let validator_signature = signer
        .sign_commitment(signature_commitment)
        .await
        .context("failed to sign DKG registration")?;

    let registration = Registration {
        version: REGISTRATION_VERSION.to_owned(),
        genesis_commitment: hex::encode(genesis_commitment.to_bytes()),
        epoch: hex::encode(epoch),
        validator_public_key: hex::encode(validator_public_key.to_bytes()),
        dkg_identity_public_key: hex::encode(StorageGroup::encode_element(&identity_public_key)),
        identity_proof_commitment: hex::encode(StorageGroup::encode_element(&proof_commitment)),
        identity_proof_response: hex::encode(proof_response.to_repr()),
        validator_signature: hex::encode(validator_signature.to_bytes()),
    };
    let registration =
        toml::to_string_pretty(&registration).context("failed to encode DKG registration")?;
    let secret = encode_identity_secret(&identity_secret);

    publish_directory(output_directory, |directory| {
        write_new_file(&directory.join(IDENTITY_SECRET_FILE), &secret, true)?;
        write_new_file(&directory.join(REGISTRATION_FILE), registration.as_bytes(), false)
    })?;

    println!("DKG identity written to {}.", output_directory.display());
    Ok(())
}

/// Builds the genesis-bound manifest and public configurations for both DKG rounds.
fn prepare(
    genesis_path: &Path,
    threshold: usize,
    epoch: &str,
    registration_paths: &[PathBuf],
    output_directory: &Path,
) -> anyhow::Result<()> {
    let epoch = decode_fixed_hex::<32>(epoch, "storage-key epoch")?;
    let genesis = read_trusted_genesis(genesis_path)?;
    let genesis_commitment = genesis.inner().header().commitment();
    let validator_keys = genesis.inner().header().validator_config().keys();

    ensure!(
        registration_paths.len() == validator_keys.len(),
        "expected {} registrations, got {}",
        validator_keys.len(),
        registration_paths.len(),
    );

    let mut registrations =
        read_validated_registrations(registration_paths, genesis_commitment, &epoch)?;

    let mut registry_entries = Vec::with_capacity(validator_keys.len());
    let mut participants = Vec::with_capacity(validator_keys.len());
    for (offset, validator_key) in validator_keys.iter().enumerate() {
        let validator_key_hex = hex::encode(validator_key.to_bytes());
        let identity_key =
            registrations.remove(validator_key.to_bytes().as_slice()).with_context(|| {
                format!("missing registration for genesis validator {validator_key_hex}")
            })?;
        let participant =
            ParticipantIndex::new(u32::try_from(offset + 1).context("too many DKG participants")?)?;
        let identity_key_hex = hex::encode(StorageGroup::encode_element(&identity_key));

        registry_entries.push((participant, identity_key));
        participants.push(ManifestParticipant {
            participant_index: participant.get(),
            validator_public_key: validator_key_hex,
            dkg_identity_public_key: identity_key_hex,
        });
    }
    ensure!(
        registrations.is_empty(),
        "registration set contains a validator outside genesis"
    );

    let beta = setup_beta()?;
    let decryption_session_id =
        derive_decryption_session_id(genesis_commitment, threshold, &epoch, &participants)?;
    let context_session_id = derive_context_session_id(decryption_session_id);
    let registry: ParticipantRegistry<StorageGroup> = ParticipantRegistry::new(registry_entries)?;
    let decryption_config =
        DkgConfig::new(threshold, decryption_session_id, beta, registry.clone())?;
    let context_config = DkgConfig::new(threshold, context_session_id, beta, registry)?;
    let decryption_config = to_wire_bytes(&decryption_config);
    let context_config = to_wire_bytes(&context_config);

    let manifest = Manifest {
        version: MANIFEST_VERSION.to_owned(),
        genesis_commitment: hex::encode(genesis_commitment.to_bytes()),
        threshold,
        epoch: hex::encode(epoch),
        beta: hex::encode(beta.to_repr()),
        decryption_session_id: hex::encode(decryption_session_id.0),
        context_session_id: hex::encode(context_session_id.0),
        decryption_config_sha256: sha256_hex(&decryption_config),
        context_config_sha256: sha256_hex(&context_config),
        participants,
    };
    let manifest = toml::to_string_pretty(&manifest).context("failed to encode DKG manifest")?;

    publish_directory(output_directory, |directory| {
        write_new_file(&directory.join(MANIFEST_FILE), manifest.as_bytes(), false)?;
        write_new_file(&directory.join(DECRYPTION_CONFIG_FILE), &decryption_config, false)?;
        write_new_file(&directory.join(CONTEXT_CONFIG_FILE), &context_config, false)
    })?;

    println!("DKG configuration written to {}.", output_directory.display());
    Ok(())
}

/// Creates this validator's two public dealings and private self shares.
fn deal<B>(
    genesis_path: &Path,
    ceremony_directory: &Path,
    identity_secret_path: &Path,
    output_directory: &Path,
    rng: &mut impl CryptoRngCore,
) -> anyhow::Result<()>
where
    B: EvrfProofBackend<StorageGroup>,
{
    let ceremony = read_ceremony(genesis_path, ceremony_directory)?;
    let identity_secret_bytes =
        Zeroizing::new(fs_err::read(identity_secret_path).with_context(|| {
            format!("failed to read DKG identity secret {}", identity_secret_path.display())
        })?);
    let identity_secret = decode_identity_secret(&identity_secret_bytes)?;
    let participant = participant_for_identity(&ceremony.manifest, &identity_secret)?;

    println!("Creating decryption dealing for participant {}.", participant.get());
    let started = Instant::now();
    let decryption = create_dealing::<StorageGroup, B>(
        participant,
        &identity_secret,
        &ceremony.decryption_config,
        rng,
    )
    .context("failed to create decryption dealing")?;
    println!(
        "Created decryption dealing for participant {} in {:.1?}.",
        participant.get(),
        started.elapsed(),
    );

    println!("Creating context dealing for participant {}.", participant.get());
    let started = Instant::now();
    let context = create_dealing_with_secret::<StorageGroup, B>(
        participant,
        &identity_secret,
        StorageScalar::zero(),
        &ceremony.context_config,
        rng,
    )
    .context("failed to create context dealing")?;
    println!(
        "Created context dealing for participant {} in {:.1?}.",
        participant.get(),
        started.elapsed(),
    );

    let decryption_message = to_wire_bytes(&decryption.message);
    let context_message = to_wire_bytes(&context.message);
    let state = PrivateState {
        participant,
        decryption_session_id: ceremony.decryption_config.session_id,
        context_session_id: ceremony.context_config.session_id,
        decryption_message_sha256: sha256(&decryption_message),
        context_message_sha256: sha256(&context_message),
        decryption_private_share: decryption.private_share.value,
        context_private_share: context.private_share.value,
    };
    let state = encode_private_state(&state);

    publish_directory(output_directory, |directory| {
        write_new_file(&directory.join(DECRYPTION_DEALING_FILE), &decryption_message, false)?;
        write_new_file(&directory.join(CONTEXT_DEALING_FILE), &context_message, false)?;
        write_new_file(&directory.join(PRIVATE_STATE_FILE), &state, true)
    })?;

    println!("DKG dealings written to {}.", output_directory.display());
    Ok(())
}

/// Signs the exact manifest and public dealings accepted by one validator.
async fn accept_transcript<B>(
    genesis_path: &Path,
    ceremony_directory: &Path,
    signer: &ValidatorSigner,
    decryption_dealing_paths: &[PathBuf],
    context_dealing_paths: &[PathBuf],
    output_directory: &Path,
) -> anyhow::Result<()>
where
    B: EvrfProofBackend<StorageGroup>,
{
    let ceremony = read_ceremony(genesis_path, ceremony_directory)?;
    let validator_public_key = signer.public_key();
    ensure!(
        ceremony
            .manifest
            .participants
            .iter()
            .any(|participant| participant.validator_public_key
                == hex::encode(validator_public_key.to_bytes())),
        "validator signing key is not part of this ceremony",
    );
    let (transcript, transcript_bytes) =
        build_transcript::<B>(&ceremony, decryption_dealing_paths, context_dealing_paths)?;
    let transcript_sha256 = sha256(&transcript_bytes);
    let signature = signer
        .sign_commitment(transcript_signature_commitment(
            ceremony.genesis_commitment,
            transcript_sha256,
        ))
        .await
        .context("failed to sign DKG transcript")?;
    let acceptance = TranscriptAcceptance {
        version: TRANSCRIPT_ACCEPTANCE_VERSION.to_owned(),
        validator_public_key: hex::encode(validator_public_key.to_bytes()),
        transcript_sha256: hex::encode(transcript_sha256),
        validator_signature: hex::encode(signature.to_bytes()),
    };
    let acceptance =
        toml::to_string_pretty(&acceptance).context("failed to encode transcript acceptance")?;
    debug_assert_eq!(transcript.manifest_sha256, hex::encode(ceremony.manifest_sha256));

    publish_directory(output_directory, |directory| {
        write_new_file(&directory.join(TRANSCRIPT_FILE), &transcript_bytes, false)?;
        write_new_file(&directory.join(TRANSCRIPT_ACCEPTANCE_FILE), acceptance.as_bytes(), false)
    })?;
    println!("DKG transcript accepted in {}.", output_directory.display());
    Ok(())
}

/// Completes both DKG rounds and publishes one validated operator bundle.
#[expect(
    clippy::too_many_arguments,
    reason = "the ceremony files stay explicit at the CLI boundary"
)]
fn finalize<B>(
    genesis_path: &Path,
    ceremony_directory: &Path,
    identity_secret_path: &Path,
    private_state_path: &Path,
    decryption_dealing_paths: &[PathBuf],
    context_dealing_paths: &[PathBuf],
    transcript_path: &Path,
    transcript_acceptance_paths: &[PathBuf],
    output_directory: &Path,
) -> anyhow::Result<()>
where
    B: EvrfProofBackend<StorageGroup>,
{
    let ceremony = read_ceremony(genesis_path, ceremony_directory)?;
    let identity_secret_bytes =
        Zeroizing::new(fs_err::read(identity_secret_path).with_context(|| {
            format!("failed to read DKG identity secret {}", identity_secret_path.display())
        })?);
    let identity_secret = decode_identity_secret(&identity_secret_bytes)?;
    let participant = participant_for_identity(&ceremony.manifest, &identity_secret)?;
    let private_state_bytes =
        Zeroizing::new(fs_err::read(private_state_path).with_context(|| {
            format!("failed to read private DKG state {}", private_state_path.display())
        })?);
    let private_state = decode_private_state(&private_state_bytes)?;
    validate_private_state(&private_state, participant, &ceremony)?;

    let (transcript, transcript_bytes) = read_transcript(transcript_path, &ceremony)?;
    let acceptances = read_transcript_acceptances(
        transcript_acceptance_paths,
        &ceremony,
        sha256(&transcript_bytes),
    )?;

    let decryption = read_dealings(decryption_dealing_paths, ceremony.manifest.participants.len())?;
    let context = read_dealings(context_dealing_paths, ceremony.manifest.participants.len())?;
    validate_dealings_against_transcript(
        &decryption.messages,
        &decryption.hashes,
        &transcript.decryption_dealings,
        &transcript.decryption_transcript_root,
    )?;
    validate_dealings_against_transcript(
        &context.messages,
        &context.hashes,
        &transcript.context_dealings,
        &transcript.context_transcript_root,
    )?;

    println!(
        "Completing decryption round for participant {} with {} dealings.",
        participant.get(),
        decryption.messages.len(),
    );
    let started = Instant::now();
    let decryption_output = complete_round::<B>(
        participant,
        &identity_secret,
        &private_state.decryption_private_share,
        private_state.decryption_message_sha256,
        decryption.messages,
        &ceremony.decryption_config,
    )
    .context("failed to complete decryption round")?;
    println!(
        "Completed decryption round for participant {} in {:.1?}.",
        participant.get(),
        started.elapsed(),
    );

    println!(
        "Completing context round for participant {} with {} dealings.",
        participant.get(),
        context.messages.len(),
    );
    let started = Instant::now();
    let context_output = complete_round::<B>(
        participant,
        &identity_secret,
        &private_state.context_private_share,
        private_state.context_message_sha256,
        context.messages,
        &ceremony.context_config,
    )
    .context("failed to complete context round")?;
    println!(
        "Completed context round for participant {} in {:.1?}.",
        participant.get(),
        started.elapsed(),
    );

    let epoch = decode_fixed_hex::<32>(&ceremony.manifest.epoch, "storage-key epoch")?;
    let material = material_from_dkg_outputs(
        &ceremony.decryption_config,
        &decryption_output,
        &ceremony.context_config,
        &context_output,
        epoch,
    )
    .context("failed to bridge DKG outputs to EHTDH1")?;
    publish_operator_bundle(
        &material,
        &ceremony,
        &transcript,
        &transcript_bytes,
        &acceptances,
        output_directory,
    )?;
    println!("Storage key bundle written to {}.", output_directory.display());
    Ok(())
}

/// Validates and publishes one final storage key bundle.
fn publish_operator_bundle(
    material: &Ehtdh1Material<StorageGroup>,
    ceremony: &Ceremony,
    transcript: &CeremonyTranscript,
    transcript_bytes: &[u8],
    acceptances: &TranscriptAcceptances,
    output_directory: &Path,
) -> anyhow::Result<()> {
    let epoch = decode_fixed_hex::<32>(&ceremony.manifest.epoch, "storage-key epoch")?;
    let setup_context = to_ehtdh1_wire_bytes(&material.setup_context);
    let public_key_set = to_ehtdh1_wire_bytes(&material.public_key_set);
    ensure!(
        sha256_hex(&public_key_set) == transcript.public_key_set_sha256,
        "generated public key set does not match accepted transcript",
    );
    let secret_share = Zeroizing::new(to_ehtdh1_wire_bytes(&material.secret_share));
    EncodedGoldenOperatorKey::new(
        StorageKeyEpoch::new(epoch),
        setup_context.clone(),
        public_key_set.clone(),
        secret_share.to_vec(),
    )
    .decode()
    .context("generated invalid storage key")?;

    publish_directory(output_directory, |directory| {
        write_new_file(&directory.join(EPOCH_FILE), ceremony.manifest.epoch.as_bytes(), false)?;
        write_new_file(&directory.join(SETUP_CONTEXT_FILE), &setup_context, false)?;
        write_new_file(&directory.join(PUBLIC_KEY_SET_FILE), &public_key_set, false)?;
        write_new_file(&directory.join(SECRET_SHARE_FILE), &secret_share, true)?;
        write_new_file(&directory.join(TRANSCRIPT_FILE), transcript_bytes, false)?;
        write_new_file(
            &directory.join(TRANSCRIPT_ACCEPTANCES_FILE),
            toml::to_string_pretty(acceptances)?.as_bytes(),
            false,
        )
    })?;
    Ok(())
}

/// Validates one final operator bundle and its genesis owner binding.
fn validate_bundle(
    genesis_path: &Path,
    ceremony_directory: &Path,
    validator_public_key: &str,
    bundle_directory: &Path,
) -> anyhow::Result<()> {
    let ceremony = read_ceremony(genesis_path, ceremony_directory)?;
    let transcript_path = bundle_directory.join(TRANSCRIPT_FILE);
    let (transcript, transcript_bytes) = read_transcript(&transcript_path, &ceremony)?;
    let acceptance_text =
        fs_err::read_to_string(bundle_directory.join(TRANSCRIPT_ACCEPTANCES_FILE))
            .context("failed to read transcript acceptances")?;
    let acceptances: TranscriptAcceptances =
        toml::from_str(&acceptance_text).context("failed to decode transcript acceptances")?;
    validate_transcript_acceptances(&acceptances, &ceremony, sha256(&transcript_bytes))?;
    let validator_public_key = decode_validator_public_key(validator_public_key)?;
    let expected = ceremony
        .manifest
        .participants
        .iter()
        .find(|entry| entry.validator_public_key == hex::encode(validator_public_key.to_bytes()))
        .context("validator public key is not part of this ceremony")?;
    let expected_participant = ParticipantIndex::new(expected.participant_index)?;
    let epoch_text = fs_err::read_to_string(bundle_directory.join(EPOCH_FILE))
        .context("failed to read storage-key epoch file")?;
    ensure!(
        epoch_text == ceremony.manifest.epoch,
        "storage-key epoch does not match manifest"
    );
    let epoch = decode_fixed_hex::<32>(&epoch_text, "storage-key epoch")?;
    let public_key_set = fs_err::read(bundle_directory.join(PUBLIC_KEY_SET_FILE))?;
    ensure!(
        sha256_hex(&public_key_set) == transcript.public_key_set_sha256,
        "bundle public key set does not match accepted transcript",
    );
    let operator_key = EncodedGoldenOperatorKey::new(
        StorageKeyEpoch::new(epoch),
        fs_err::read(bundle_directory.join(SETUP_CONTEXT_FILE))?,
        public_key_set,
        fs_err::read(bundle_directory.join(SECRET_SHARE_FILE))?,
    )
    .decode()
    .context("invalid storage key bundle")?;
    ensure!(
        operator_key.participant() == expected_participant,
        "bundle belongs to participant {}, expected {}",
        operator_key.participant().get(),
        expected_participant.get(),
    );
    validate_setup_context(operator_key.setup_context(), &ceremony)?;
    ensure!(
        operator_key.setup_context().decryption_transcript_root
            == decode_fixed_hex::<32>(
                &transcript.decryption_transcript_root,
                "decryption transcript root",
            )?
            && operator_key.setup_context().context_transcript_root
                == decode_fixed_hex::<32>(
                    &transcript.context_transcript_root,
                    "context transcript root",
                )?,
        "bundle transcript roots do not match accepted transcript",
    );
    println!("Storage key bundle is valid for participant {}.", expected_participant.get());
    Ok(())
}

/// Validates the four-file bundle used by local development fixtures.
fn validate_fixture_bundle(
    bundle_directory: &Path,
    expected_participant: u32,
) -> anyhow::Result<()> {
    let expected_participant = ParticipantIndex::new(expected_participant)?;
    let epoch = fs_err::read_to_string(bundle_directory.join(EPOCH_FILE))
        .context("failed to read storage-key epoch file")?;
    let epoch = decode_fixed_hex::<32>(&epoch, "storage-key epoch")?;
    let operator_key = EncodedGoldenOperatorKey::new(
        StorageKeyEpoch::new(epoch),
        fs_err::read(bundle_directory.join(SETUP_CONTEXT_FILE))?,
        fs_err::read(bundle_directory.join(PUBLIC_KEY_SET_FILE))?,
        fs_err::read(bundle_directory.join(SECRET_SHARE_FILE))?,
    )
    .decode()
    .context("invalid storage key fixture")?;
    ensure!(
        operator_key.participant() == expected_participant,
        "fixture belongs to participant {}, expected {}",
        operator_key.participant().get(),
        expected_participant.get(),
    );
    println!("Storage key fixture is valid for participant {}.", expected_participant.get());
    Ok(())
}

/// Reads and validates one public DKG registration.
fn read_registration(path: &Path) -> anyhow::Result<Registration> {
    let contents = fs_err::read_to_string(path)
        .with_context(|| format!("failed to read registration {}", path.display()))?;
    let registration: Registration = toml::from_str(&contents)
        .with_context(|| format!("failed to decode registration {}", path.display()))?;
    ensure!(
        registration.version == REGISTRATION_VERSION,
        "unsupported registration version in {}",
        path.display(),
    );
    Ok(registration)
}

/// Reads registrations and verifies their genesis binding and validator signatures.
fn read_validated_registrations(
    paths: &[PathBuf],
    genesis_commitment: Word,
    expected_epoch: &[u8; 32],
) -> anyhow::Result<BTreeMap<Vec<u8>, <StorageGroup as GoldenGroup>::Element>> {
    let mut registrations = BTreeMap::new();
    let mut identity_keys = BTreeSet::new();
    for path in paths {
        let registration = read_registration(path)?;
        let validator_key = decode_validator_public_key(&registration.validator_public_key)?;
        let identity_key = decode_identity_public_key(&registration.dkg_identity_public_key)?;
        let proof_commitment =
            decode_non_identity_element(&registration.identity_proof_commitment, "identity proof")?;
        let proof_response =
            decode_scalar(&registration.identity_proof_response, "identity proof response")?;
        let signature = decode_validator_signature(&registration.validator_signature)?;

        ensure!(
            registration.genesis_commitment == hex::encode(genesis_commitment.to_bytes()),
            "registration in {} belongs to a different genesis block",
            path.display(),
        );
        ensure!(
            registration.epoch == hex::encode(expected_epoch),
            "registration in {} belongs to a different storage-key epoch",
            path.display(),
        );
        ensure!(
            signature.verify(
                registration_signature_commitment(
                    genesis_commitment,
                    expected_epoch,
                    &validator_key,
                    &identity_key,
                    &proof_commitment,
                    &proof_response,
                ),
                &validator_key,
            ),
            "invalid validator signature in {}",
            path.display(),
        );
        ensure!(
            verify_identity_proof(
                genesis_commitment,
                expected_epoch,
                &validator_key,
                &identity_key,
                &proof_commitment,
                &proof_response,
            )?,
            "invalid DKG identity proof in {}",
            path.display(),
        );
        ensure!(
            identity_keys.insert(StorageGroup::encode_element(&identity_key).as_ref().to_vec()),
            "duplicate DKG identity public key in {}",
            path.display(),
        );
        ensure!(
            registrations.insert(validator_key.to_bytes(), identity_key).is_none(),
            "duplicate validator registration in {}",
            path.display(),
        );
    }
    Ok(registrations)
}

/// Reads a ceremony directory and checks every public value against genesis.
fn read_ceremony(genesis_path: &Path, directory: &Path) -> anyhow::Result<Ceremony> {
    let manifest_path = directory.join(MANIFEST_FILE);
    let manifest_text =
        fs_err::read_to_string(&manifest_path).context("failed to read DKG manifest")?;
    let manifest: Manifest =
        toml::from_str(&manifest_text).context("failed to decode DKG manifest")?;
    ensure!(manifest.version == MANIFEST_VERSION, "unsupported DKG manifest version");

    let genesis = read_trusted_genesis(genesis_path)?;
    let genesis_commitment = genesis.inner().header().commitment();
    ensure!(
        manifest.genesis_commitment == hex::encode(genesis_commitment.to_bytes()),
        "DKG manifest belongs to a different genesis block",
    );
    let epoch = decode_fixed_hex::<32>(&manifest.epoch, "storage-key epoch")?;

    let decryption_bytes = fs_err::read(directory.join(DECRYPTION_CONFIG_FILE))
        .context("failed to read decryption configuration")?;
    let context_bytes = fs_err::read(directory.join(CONTEXT_CONFIG_FILE))
        .context("failed to read context configuration")?;
    ensure!(
        sha256_hex(&decryption_bytes) == manifest.decryption_config_sha256,
        "decryption configuration digest does not match manifest",
    );
    ensure!(
        sha256_hex(&context_bytes) == manifest.context_config_sha256,
        "context configuration digest does not match manifest",
    );
    let decryption_config = from_core_wire_bytes::<DkgConfig<StorageGroup>>(&decryption_bytes)
        .context("invalid decryption configuration")?;
    let context_config = from_core_wire_bytes::<DkgConfig<StorageGroup>>(&context_bytes)
        .context("invalid context configuration")?;

    ensure!(decryption_config.threshold == manifest.threshold, "threshold mismatch");
    ensure!(context_config.threshold == manifest.threshold, "context threshold mismatch");
    let expected_beta = setup_beta()?;
    ensure!(
        decryption_config.beta == expected_beta
            && hex::encode(expected_beta.to_repr()) == manifest.beta
            && context_config.beta == decryption_config.beta,
        "DKG beta mismatch",
    );
    let expected_session = derive_decryption_session_id(
        genesis_commitment,
        manifest.threshold,
        &epoch,
        &manifest.participants,
    )?;
    ensure!(
        decryption_config.session_id == expected_session
            && hex::encode(expected_session.0) == manifest.decryption_session_id,
        "decryption session mismatch",
    );
    ensure!(
        hex::encode(context_config.session_id.0) == manifest.context_session_id
            && context_config.session_id == derive_context_session_id(decryption_config.session_id),
        "context session mismatch",
    );
    ensure!(
        context_config.registry.root() == decryption_config.registry.root(),
        "registry mismatch between DKG rounds",
    );

    let validator_keys = genesis.inner().header().validator_config().keys();
    ensure!(
        manifest.participants.len() == validator_keys.len(),
        "manifest participant count does not match genesis",
    );
    for (offset, (entry, validator_key)) in
        manifest.participants.iter().zip(validator_keys).enumerate()
    {
        let participant =
            ParticipantIndex::new(u32::try_from(offset + 1).context("too many DKG participants")?)?;
        ensure!(entry.participant_index == participant.get(), "non-canonical participant order");
        ensure!(
            entry.validator_public_key == hex::encode(validator_key.to_bytes()),
            "manifest validator order does not match genesis",
        );
        let expected_identity = decode_identity_public_key(&entry.dkg_identity_public_key)?;
        ensure!(
            decryption_config.registry.public_key(participant)? == &expected_identity
                && context_config.registry.public_key(participant)? == &expected_identity,
            "manifest identity does not match DKG registry",
        );
    }

    Ok(Ceremony {
        manifest,
        manifest_sha256: sha256(manifest_text.as_bytes()),
        genesis_commitment,
        decryption_config,
        context_config,
    })
}

/// Returns the fixed public eVRF setup coefficient for this storage DKG backend.
fn setup_beta() -> anyhow::Result<StorageScalar> {
    StorageScalar::hash_to_scalar(SETUP_BETA_DOMAIN, StorageGroup::BACKEND_ID.as_bytes())
        .context("failed to derive storage key DKG beta")
}

/// Derives one ceremony session from its agreed public policy and participant registry.
fn derive_decryption_session_id(
    genesis_commitment: Word,
    threshold: usize,
    epoch: &[u8; 32],
    participants: &[ManifestParticipant],
) -> anyhow::Result<SessionId> {
    let mut digest = Sha256::new();
    digest.update(DECRYPTION_SESSION_DOMAIN);
    digest.update(u64::try_from(StorageGroup::BACKEND_ID.len())?.to_be_bytes());
    digest.update(StorageGroup::BACKEND_ID.as_bytes());
    digest.update(genesis_commitment.to_bytes());
    digest.update(u64::try_from(threshold)?.to_be_bytes());
    digest.update(epoch);
    digest.update(u64::try_from(participants.len())?.to_be_bytes());
    for participant in participants {
        digest.update(participant.participant_index.to_be_bytes());
        let validator_key = decode_validator_public_key(&participant.validator_public_key)?;
        let identity_key = decode_identity_public_key(&participant.dkg_identity_public_key)?;
        digest.update(validator_key.to_bytes());
        digest.update(StorageGroup::encode_element(&identity_key).as_ref());
    }
    Ok(SessionId(digest.finalize().into()))
}

/// Returns the manifest participant whose public identity matches a secret.
fn participant_for_identity(
    manifest: &Manifest,
    identity_secret: &StorageScalar,
) -> anyhow::Result<ParticipantIndex> {
    let public_key = StorageGroup::mul_generator(identity_secret);
    let public_key = hex::encode(StorageGroup::encode_element(&public_key));
    let entry = manifest
        .participants
        .iter()
        .find(|entry| entry.dkg_identity_public_key == public_key)
        .context("DKG identity is not part of this ceremony")?;
    Ok(ParticipantIndex::new(entry.participant_index)?)
}

/// Reads exactly one public dealing from every ceremony participant.
fn read_dealings(paths: &[PathBuf], expected: usize) -> anyhow::Result<DealingSet> {
    ensure!(paths.len() == expected, "expected {expected} dealings, got {}", paths.len());
    let mut dealings = BTreeMap::new();
    let mut hashes = BTreeMap::new();
    for path in paths {
        let bytes = fs_err::read(path)
            .with_context(|| format!("failed to read dealing {}", path.display()))?;
        let message = from_core_wire_bytes::<DealerMessage<StorageGroup>>(&bytes)
            .with_context(|| format!("invalid dealing {}", path.display()))?;
        let dealer = message.dealer;
        ensure!(
            dealings.insert(dealer, message).is_none(),
            "duplicate dealing from participant {}",
            dealer.get(),
        );
        hashes.insert(dealer, sha256_hex(&bytes));
    }
    ensure!(dealings.len() == expected, "dealing set is incomplete");
    let hashes = hashes
        .into_iter()
        .map(|(participant, sha256)| TranscriptDealing {
            participant_index: participant.get(),
            sha256,
        })
        .collect();
    Ok(DealingSet { messages: dealings, hashes })
}

/// Builds the canonical transcript over one manifest and both dealing rounds.
fn build_transcript<B>(
    ceremony: &Ceremony,
    decryption_paths: &[PathBuf],
    context_paths: &[PathBuf],
) -> anyhow::Result<(CeremonyTranscript, Vec<u8>)>
where
    B: EvrfProofBackend<StorageGroup>,
{
    let expected = ceremony.manifest.participants.len();
    let decryption = read_dealings(decryption_paths, expected)?;
    let context = read_dealings(context_paths, expected)?;
    for message in decryption.messages.values() {
        verify_dealing::<StorageGroup, B>(message, &ceremony.decryption_config)
            .context("invalid decryption dealing")?;
    }
    for message in context.messages.values() {
        verify_dealing::<StorageGroup, B>(message, &ceremony.context_config)
            .context("invalid context dealing")?;
    }
    let public_key_set = public_key_set_from_dealings(
        &decryption.messages,
        &context.messages,
        &ceremony.decryption_config,
    )?;
    let transcript = CeremonyTranscript {
        version: TRANSCRIPT_VERSION.to_owned(),
        manifest_sha256: hex::encode(ceremony.manifest_sha256),
        decryption_transcript_root: hex::encode(completion_root(&decryption.messages)),
        context_transcript_root: hex::encode(completion_root(&context.messages)),
        public_key_set_sha256: sha256_hex(&to_ehtdh1_wire_bytes(&public_key_set)),
        decryption_dealings: decryption.hashes,
        context_dealings: context.hashes,
    };
    let bytes = toml::to_string_pretty(&transcript)
        .context("failed to encode DKG transcript")?
        .into_bytes();
    Ok((transcript, bytes))
}

/// Reads one canonical transcript and checks its manifest binding.
fn read_transcript(
    path: &Path,
    ceremony: &Ceremony,
) -> anyhow::Result<(CeremonyTranscript, Vec<u8>)> {
    let bytes = fs_err::read(path)
        .with_context(|| format!("failed to read DKG transcript {}", path.display()))?;
    let text = std::str::from_utf8(&bytes).context("DKG transcript is not UTF-8")?;
    let transcript: CeremonyTranscript =
        toml::from_str(text).context("failed to decode DKG transcript")?;
    ensure!(transcript.version == TRANSCRIPT_VERSION, "unsupported DKG transcript version");
    ensure!(
        transcript.manifest_sha256 == hex::encode(ceremony.manifest_sha256),
        "DKG transcript belongs to another manifest",
    );
    decode_fixed_hex::<32>(&transcript.decryption_transcript_root, "decryption transcript root")?;
    decode_fixed_hex::<32>(&transcript.context_transcript_root, "context transcript root")?;
    decode_fixed_hex::<32>(&transcript.public_key_set_sha256, "public key set digest")?;
    let canonical =
        toml::to_string_pretty(&transcript).context("failed to encode DKG transcript")?;
    ensure!(canonical.as_bytes() == bytes, "non-canonical DKG transcript");
    Ok((transcript, bytes))
}

/// Reads, sorts, and verifies every validator's transcript acceptance.
fn read_transcript_acceptances(
    paths: &[PathBuf],
    ceremony: &Ceremony,
    transcript_sha256: [u8; 32],
) -> anyhow::Result<TranscriptAcceptances> {
    let mut acceptances = Vec::with_capacity(paths.len());
    for path in paths {
        let text = fs_err::read_to_string(path)
            .with_context(|| format!("failed to read transcript acceptance {}", path.display()))?;
        acceptances.push(toml::from_str(&text).with_context(|| {
            format!("failed to decode transcript acceptance {}", path.display())
        })?);
    }
    let acceptances = TranscriptAcceptances { acceptances };
    validate_transcript_acceptances(&acceptances, ceremony, transcript_sha256)?;

    let by_key = acceptances
        .acceptances
        .into_iter()
        .map(|acceptance| (acceptance.validator_public_key.clone(), acceptance))
        .collect::<BTreeMap<_, _>>();
    let mut ordered = Vec::with_capacity(by_key.len());
    for participant in &ceremony.manifest.participants {
        ordered.push(
            by_key
                .get(&participant.validator_public_key)
                .context("missing transcript acceptance")?
                .to_owned(),
        );
    }
    Ok(TranscriptAcceptances { acceptances: ordered })
}

/// Verifies unanimous genesis-validator acceptance of one exact transcript.
fn validate_transcript_acceptances(
    acceptances: &TranscriptAcceptances,
    ceremony: &Ceremony,
    transcript_sha256: [u8; 32],
) -> anyhow::Result<()> {
    ensure!(
        acceptances.acceptances.len() == ceremony.manifest.participants.len(),
        "expected {} transcript acceptances, got {}",
        ceremony.manifest.participants.len(),
        acceptances.acceptances.len(),
    );
    let expected_digest = hex::encode(transcript_sha256);
    let commitment =
        transcript_signature_commitment(ceremony.genesis_commitment, transcript_sha256);
    let mut accepted = BTreeSet::new();
    for acceptance in &acceptances.acceptances {
        ensure!(
            acceptance.version == TRANSCRIPT_ACCEPTANCE_VERSION,
            "unsupported transcript acceptance version",
        );
        ensure!(
            acceptance.transcript_sha256 == expected_digest,
            "transcript acceptance belongs to another transcript",
        );
        let validator_key = decode_validator_public_key(&acceptance.validator_public_key)?;
        let signature = decode_validator_signature(&acceptance.validator_signature)?;
        ensure!(
            signature.verify(commitment, &validator_key),
            "invalid transcript acceptance signature",
        );
        ensure!(
            accepted.insert(acceptance.validator_public_key.clone()),
            "duplicate transcript acceptance",
        );
    }
    let expected = ceremony
        .manifest
        .participants
        .iter()
        .map(|participant| participant.validator_public_key.clone())
        .collect::<BTreeSet<_>>();
    ensure!(accepted == expected, "transcript acceptances do not match genesis validators");
    Ok(())
}

/// Recomputes one round's canonical dealing hashes and completion root.
fn validate_dealings_against_transcript(
    dealings: &BTreeMap<ParticipantIndex, DealerMessage<StorageGroup>>,
    actual_hashes: &[TranscriptDealing],
    expected_hashes: &[TranscriptDealing],
    expected_root: &str,
) -> anyhow::Result<()> {
    ensure!(actual_hashes == expected_hashes, "dealings do not match accepted transcript");
    ensure!(
        hex::encode(completion_root(dealings)) == expected_root,
        "dealing roots do not match accepted transcript",
    );
    Ok(())
}

/// Derives the EHTDH1 public key set from the accepted Feldman commitments.
fn public_key_set_from_dealings(
    decryption: &BTreeMap<ParticipantIndex, DealerMessage<StorageGroup>>,
    context: &BTreeMap<ParticipantIndex, DealerMessage<StorageGroup>>,
    config: &DkgConfig<StorageGroup>,
) -> anyhow::Result<PublicKeySet<StorageGroup>> {
    let (joint_public_key, decryption_shares) = aggregate_public_output(decryption, config)?;
    let (context_public_key, context_shares) = aggregate_public_output(context, config)?;
    ensure!(
        bool::from(StorageGroup::is_identity(&context_public_key)),
        "context dealings do not share zero",
    );
    let public_shares = config
        .registry
        .indexes()
        .map(|participant| {
            Ok((
                participant,
                PublicShare {
                    decryption: *decryption_shares
                        .get(&participant)
                        .context("missing decryption public share")?,
                    context: *context_shares
                        .get(&participant)
                        .context("missing context public share")?,
                },
            ))
        })
        .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
    PublicKeySet::new(config.threshold, joint_public_key, public_shares)
        .context("dealings produce an invalid public key set")
}

/// Aggregates the public key and participant shares from one dealing round.
fn aggregate_public_output(
    dealings: &BTreeMap<ParticipantIndex, DealerMessage<StorageGroup>>,
    config: &DkgConfig<StorageGroup>,
) -> anyhow::Result<PublicOutput> {
    let mut public_key = StorageGroup::identity();
    for message in dealings.values() {
        public_key = StorageGroup::add(&public_key, &message.commitment.public_key());
    }
    let mut public_shares = BTreeMap::new();
    for participant in config.registry.indexes() {
        let mut share = StorageGroup::identity();
        for message in dealings.values() {
            share = StorageGroup::add(&share, &message.commitment.public_key_share(participant)?);
        }
        public_shares.insert(participant, share);
    }
    Ok((public_key, public_shares))
}

/// Reproduces the completion transcript root from public dealings.
fn completion_root(dealings: &BTreeMap<ParticipantIndex, DealerMessage<StorageGroup>>) -> [u8; 32] {
    let mut transcript = TranscriptBuilder::with_prefix(b"golden-core-v1", b"completion");
    transcript.bytes(b"backend", StorageGroup::BACKEND_ID.as_bytes());
    transcript.usize(b"dealings-len", dealings.len());
    for (dealer, message) in dealings {
        transcript.participant(b"dealer", *dealer);
        transcript.bytes(b"dealing-root", &message.transcript_root);
    }
    transcript.root()
}

/// Commits a validator signature to one exact public ceremony transcript.
fn transcript_signature_commitment(genesis_commitment: Word, transcript_sha256: [u8; 32]) -> Word {
    let mut bytes = Vec::with_capacity(
        TRANSCRIPT_SIGNATURE_DOMAIN.len() + Word::SERIALIZED_SIZE + transcript_sha256.len(),
    );
    bytes.extend_from_slice(TRANSCRIPT_SIGNATURE_DOMAIN);
    bytes.extend_from_slice(&genesis_commitment.to_bytes());
    bytes.extend_from_slice(&transcript_sha256);
    Rpo256::hash(&bytes)
}

/// Completes one DKG round from public messages and the local self share.
fn complete_round<B>(
    participant: ParticipantIndex,
    identity_secret: &StorageScalar,
    private_share: &StorageScalar,
    expected_own_message_sha256: [u8; 32],
    mut dealings: BTreeMap<ParticipantIndex, DealerMessage<StorageGroup>>,
    config: &DkgConfig<StorageGroup>,
) -> anyhow::Result<golden_core::DkgOutput<StorageGroup>>
where
    B: EvrfProofBackend<StorageGroup>,
{
    let own_message = dealings.remove(&participant).context("missing local dealing")?;
    ensure!(
        sha256(&to_wire_bytes(&own_message)) == expected_own_message_sha256,
        "local dealing does not match private state",
    );
    let own_dealing = DkgDealing {
        message: own_message,
        private_share: Share { participant, value: *private_share },
    };
    Ok(complete::<StorageGroup, B>(
        participant,
        identity_secret,
        &own_dealing,
        &dealings,
        config,
    )?)
}

/// Checks a generated setup context against the public ceremony.
fn validate_setup_context(context: &SetupContext, ceremony: &Ceremony) -> anyhow::Result<()> {
    ensure!(context.threshold == ceremony.manifest.threshold, "setup threshold mismatch");
    ensure!(
        context.registry_root == ceremony.decryption_config.registry.root(),
        "setup registry mismatch",
    );
    ensure!(
        context.decryption_session_id == ceremony.decryption_config.session_id
            && context.context_session_id == ceremony.context_config.session_id,
        "setup session mismatch",
    );
    ensure!(
        context.epoch == decode_fixed_hex::<32>(&ceremony.manifest.epoch, "epoch")?,
        "setup epoch mismatch"
    );
    let participants = ceremony
        .manifest
        .participants
        .iter()
        .map(|entry| ParticipantIndex::new(entry.participant_index))
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(context.participants == participants, "setup participant mismatch");
    Ok(())
}

/// Encodes private self shares with their participant, sessions, and public messages.
fn encode_private_state(state: &PrivateState) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        PRIVATE_STATE_MAGIC.len() + 4 + 4 * 32 + 2 * StorageScalar::REPR_BYTES,
    ));
    bytes.extend_from_slice(PRIVATE_STATE_MAGIC);
    bytes.extend_from_slice(&state.participant.get().to_be_bytes());
    bytes.extend_from_slice(&state.decryption_session_id.0);
    bytes.extend_from_slice(&state.context_session_id.0);
    bytes.extend_from_slice(&state.decryption_message_sha256);
    bytes.extend_from_slice(&state.context_message_sha256);
    bytes.extend_from_slice(state.decryption_private_share.to_repr().as_ref());
    bytes.extend_from_slice(state.context_private_share.to_repr().as_ref());
    bytes
}

/// Decodes private self shares and rejects trailing or non-canonical data.
fn decode_private_state(bytes: &[u8]) -> anyhow::Result<PrivateState> {
    let mut bytes = bytes
        .strip_prefix(PRIVATE_STATE_MAGIC)
        .context("invalid private DKG state format")?;
    let expected = 4 + 4 * 32 + 2 * StorageScalar::REPR_BYTES;
    ensure!(bytes.len() == expected, "invalid private DKG state length");
    let participant = ParticipantIndex::new(u32::from_be_bytes(take_array(&mut bytes)?))?;
    let decryption_session_id = SessionId(take_array(&mut bytes)?);
    let context_session_id = SessionId(take_array(&mut bytes)?);
    let decryption_message_sha256 = take_array(&mut bytes)?;
    let context_message_sha256 = take_array(&mut bytes)?;
    let decryption_private_share = take_scalar(&mut bytes)?;
    let context_private_share = take_scalar(&mut bytes)?;
    ensure!(bytes.is_empty(), "trailing private DKG state bytes");
    Ok(PrivateState {
        participant,
        decryption_session_id,
        context_session_id,
        decryption_message_sha256,
        context_message_sha256,
        decryption_private_share,
        context_private_share,
    })
}

/// Checks that private state belongs to this participant and ceremony.
fn validate_private_state(
    state: &PrivateState,
    participant: ParticipantIndex,
    ceremony: &Ceremony,
) -> anyhow::Result<()> {
    ensure!(
        state.participant == participant,
        "private DKG state belongs to another participant"
    );
    ensure!(
        state.decryption_session_id == ceremony.decryption_config.session_id
            && state.context_session_id == ceremony.context_config.session_id,
        "private DKG state belongs to another ceremony",
    );
    Ok(())
}

/// Removes and returns one fixed-size prefix.
fn take_array<const N: usize>(bytes: &mut &[u8]) -> anyhow::Result<[u8; N]> {
    ensure!(bytes.len() >= N, "truncated private DKG state");
    let (head, tail) = bytes.split_at(N);
    *bytes = tail;
    Ok(head.try_into().expect("fixed-size slice"))
}

/// Removes and decodes one canonical scalar.
fn take_scalar(bytes: &mut &[u8]) -> anyhow::Result<StorageScalar> {
    let scalar = take_array::<{ StorageScalar::REPR_BYTES }>(bytes)?;
    let repr = <StorageScalar as GoldenScalar>::Repr::try_from(scalar.to_vec())
        .map_err(|_| anyhow::anyhow!("invalid private DKG scalar length"))?;
    StorageScalar::from_repr(&repr).context("invalid private DKG scalar")
}

/// Reads and validates the trusted genesis block used by the ceremony.
fn read_trusted_genesis(path: &Path) -> anyhow::Result<GenesisBlock> {
    read_genesis_block(path).context("failed to validate genesis block")
}

/// Commits a validator signature to one genesis-bound DKG identity registration.
fn registration_signature_commitment(
    genesis_commitment: Word,
    epoch: &[u8; 32],
    validator_public_key: &PublicKey,
    identity_public_key: &<StorageGroup as GoldenGroup>::Element,
    proof_commitment: &<StorageGroup as GoldenGroup>::Element,
    proof_response: &StorageScalar,
) -> Word {
    let mut bytes = Vec::with_capacity(
        REGISTRATION_SIGNATURE_DOMAIN.len()
            + Word::SERIALIZED_SIZE
            + epoch.len()
            + validator_public_key.to_bytes().len()
            + StorageGroup::ELEMENT_REPR_BYTES * 2
            + StorageScalar::REPR_BYTES,
    );
    bytes.extend_from_slice(REGISTRATION_SIGNATURE_DOMAIN);
    bytes.extend_from_slice(&genesis_commitment.to_bytes());
    bytes.extend_from_slice(epoch);
    bytes.extend_from_slice(&validator_public_key.to_bytes());
    bytes.extend_from_slice(StorageGroup::encode_element(identity_public_key).as_ref());
    bytes.extend_from_slice(StorageGroup::encode_element(proof_commitment).as_ref());
    bytes.extend_from_slice(proof_response.to_repr().as_ref());
    Rpo256::hash(&bytes)
}

/// Creates a proof that the registering validator knows its DKG identity secret.
fn create_identity_proof(
    genesis_commitment: Word,
    epoch: &[u8; 32],
    validator_public_key: &PublicKey,
    identity_secret: &StorageScalar,
    rng: &mut impl CryptoRngCore,
) -> anyhow::Result<(StorageElement, StorageScalar)> {
    let identity_public_key = StorageGroup::mul_generator(identity_secret);
    let nonce = loop {
        let nonce = StorageScalar::random(rng);
        if !bool::from(nonce.is_zero()) {
            break nonce;
        }
    };
    let commitment = StorageGroup::mul_generator(&nonce);
    let challenge = identity_proof_challenge(
        genesis_commitment,
        epoch,
        validator_public_key,
        &identity_public_key,
        &commitment,
    )?;
    let response = nonce.add(&challenge.mul(identity_secret));
    Ok((commitment, response))
}

/// Checks a proof that the registering validator knows its DKG identity secret.
fn verify_identity_proof(
    genesis_commitment: Word,
    epoch: &[u8; 32],
    validator_public_key: &PublicKey,
    identity_public_key: &StorageElement,
    commitment: &StorageElement,
    response: &StorageScalar,
) -> anyhow::Result<bool> {
    let challenge = identity_proof_challenge(
        genesis_commitment,
        epoch,
        validator_public_key,
        identity_public_key,
        commitment,
    )?;
    let expected =
        StorageGroup::add(commitment, &StorageGroup::mul(identity_public_key, &challenge));
    Ok(StorageGroup::mul_generator(response) == expected)
}

/// Derives the Fiat-Shamir challenge for one DKG identity proof.
fn identity_proof_challenge(
    genesis_commitment: Word,
    epoch: &[u8; 32],
    validator_public_key: &PublicKey,
    identity_public_key: &StorageElement,
    commitment: &StorageElement,
) -> anyhow::Result<StorageScalar> {
    let mut message = Vec::with_capacity(
        std::mem::size_of::<u64>()
            + StorageGroup::BACKEND_ID.len()
            + Word::SERIALIZED_SIZE
            + epoch.len()
            + validator_public_key.to_bytes().len()
            + StorageGroup::ELEMENT_REPR_BYTES * 2,
    );
    message.extend_from_slice(&u64::try_from(StorageGroup::BACKEND_ID.len())?.to_be_bytes());
    message.extend_from_slice(StorageGroup::BACKEND_ID.as_bytes());
    message.extend_from_slice(&genesis_commitment.to_bytes());
    message.extend_from_slice(epoch);
    message.extend_from_slice(&validator_public_key.to_bytes());
    message.extend_from_slice(StorageGroup::encode_element(identity_public_key).as_ref());
    message.extend_from_slice(StorageGroup::encode_element(commitment).as_ref());
    StorageScalar::hash_to_scalar(IDENTITY_PROOF_DOMAIN, &message)
        .context("failed to derive DKG identity proof challenge")
}

/// Parses a validator public key and requires its canonical hex form.
fn decode_validator_public_key(value: &str) -> anyhow::Result<PublicKey> {
    let bytes = decode_hex(value, "validator public key")?;
    let public_key = PublicKey::read_from_bytes(&bytes).context("invalid validator public key")?;
    ensure!(public_key.to_bytes() == bytes, "non-canonical validator public key");
    Ok(public_key)
}

/// Parses a canonical validator registration signature.
fn decode_validator_signature(value: &str) -> anyhow::Result<Signature> {
    let bytes = decode_hex(value, "validator signature")?;
    let signature = Signature::read_from_bytes(&bytes).context("invalid validator signature")?;
    ensure!(signature.to_bytes() == bytes, "non-canonical validator signature");
    Ok(signature)
}

/// Parses a non-identity DKG public key.
fn decode_identity_public_key(
    value: &str,
) -> anyhow::Result<<StorageGroup as GoldenGroup>::Element> {
    decode_non_identity_element(value, "DKG identity public key")
}

/// Parses a canonical non-identity group element.
fn decode_non_identity_element(value: &str, name: &str) -> anyhow::Result<StorageElement> {
    let bytes = decode_hex(value, name)?;
    let repr = <StorageGroup as GoldenGroup>::ElementRepr::try_from(bytes)
        .map_err(|_| anyhow::anyhow!("invalid {name} length"))?;
    let public_key =
        StorageGroup::decode_element(&repr).with_context(|| format!("invalid {name}"))?;
    ensure!(!bool::from(StorageGroup::is_identity(&public_key)), "{name} is the identity");
    Ok(public_key)
}

/// Parses a canonical scalar.
fn decode_scalar(value: &str, name: &str) -> anyhow::Result<StorageScalar> {
    let bytes = decode_hex(value, name)?;
    let repr = <StorageScalar as GoldenScalar>::Repr::try_from(bytes)
        .map_err(|_| anyhow::anyhow!("invalid {name} length"))?;
    StorageScalar::from_repr(&repr).with_context(|| format!("invalid {name}"))
}

/// Encodes a private DKG identity with a fixed format marker.
fn encode_identity_secret(secret: &StorageScalar) -> Zeroizing<Vec<u8>> {
    let mut encoded =
        Zeroizing::new(Vec::with_capacity(IDENTITY_SECRET_MAGIC.len() + StorageScalar::REPR_BYTES));
    encoded.extend_from_slice(IDENTITY_SECRET_MAGIC);
    encoded.extend_from_slice(secret.to_repr().as_ref());
    encoded
}

/// Decodes a private DKG identity and rejects malformed or zero scalars.
fn decode_identity_secret(bytes: &[u8]) -> anyhow::Result<StorageScalar> {
    let scalar_bytes = bytes
        .strip_prefix(IDENTITY_SECRET_MAGIC)
        .context("invalid DKG identity secret format")?;
    ensure!(
        scalar_bytes.len() == StorageScalar::REPR_BYTES,
        "invalid DKG identity secret length",
    );
    let repr = <StorageScalar as GoldenScalar>::Repr::try_from(scalar_bytes.to_vec())
        .map_err(|_| anyhow::anyhow!("invalid DKG identity secret length"))?;
    let secret = StorageScalar::from_repr(&repr).context("invalid DKG identity secret")?;
    ensure!(!bool::from(secret.is_zero()), "DKG identity secret is zero");
    Ok(secret)
}

/// Publishes a complete set of ceremony files under a new directory.
fn publish_directory(
    output_directory: &Path,
    write: impl FnOnce(&Path) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    ensure!(!output_directory.exists(), "output directory already exists");
    let parent = output_directory.parent().unwrap_or_else(|| Path::new("."));
    fs_err::create_dir_all(parent).context("failed to create output parent directory")?;
    let temporary = tempfile::Builder::new()
        .prefix(".storage-key-dkg-")
        .tempdir_in(parent)
        .context("failed to create temporary output directory")?;
    write(temporary.path())?;
    fs_err::rename(temporary.path(), output_directory)
        .context("failed to publish output directory")?;
    Ok(())
}

/// Creates one ceremony file without replacing an existing file.
fn write_new_file(path: &Path, bytes: &[u8], private: bool) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all().with_context(|| format!("failed to sync {}", path.display()))?;
    Ok(())
}

/// Parses canonical lowercase hex.
fn decode_hex(value: &str, name: &str) -> anyhow::Result<Vec<u8>> {
    ensure!(
        value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{name} must use lowercase hex",
    );
    let bytes = hex::decode(value).with_context(|| format!("invalid {name}"))?;
    ensure!(hex::encode(&bytes) == value, "non-canonical {name}");
    Ok(bytes)
}

/// Parses a fixed-size canonical hex value.
fn decode_fixed_hex<const N: usize>(value: &str, name: &str) -> anyhow::Result<[u8; N]> {
    decode_hex(value, name)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must be {N} bytes"))
}

/// Returns the SHA-256 digest of one public ceremony artifact.
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha256(bytes))
}

/// Returns the SHA-256 digest of one artifact.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
