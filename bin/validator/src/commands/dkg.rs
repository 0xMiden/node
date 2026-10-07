//! Runs live storage-key ceremonies over a direct mesh of authenticated, trusted validators.
//!
//! The ceremony assumes that all participants follow the protocol. It does not handle Byzantine
//! participants or equivocation. Transcript comparisons abort on detected mismatches but do not
//! provide Byzantine fault tolerance. Completion follows local bundle persistence.

use std::io::Write;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, ensure};
use fs_err::PathExt;
use golden_core::ParticipantIndex;
use iroh::{EndpointAddr, EndpointId, SecretKey as IrohSecretKey};
use miden_node_tracing::info;
use miden_node_utils::shutdown::CancellationToken;
use zeroize::Zeroizing;

use self::ceremony::completion::Completion;
use super::{ValidatorSigningKey, ValidatorStorageKey};

mod ceremony;
mod wire;

#[cfg(test)]
mod tests;

/// Inputs for one peer-to-peer DKG command.
#[derive(clap::Args)]
pub struct DkgOptions {
    #[command(subcommand)]
    command: DkgCommand,
}

/// Peer-to-peer DKG commands.
#[derive(clap::Subcommand)]
enum DkgCommand {
    /// Generates this validator's persistent peer-to-peer endpoint identity.
    GenerateEndpoint {
        /// Output file for the peer-to-peer endpoint secret. The file must not already exist.
        #[arg(long, value_name = "FILE")]
        output_file: PathBuf,
    },

    /// Runs a live peer-to-peer DKG ceremony and writes this validator's storage-key bundle.
    Participate(Box<ParticipateOptions>),

    /// Checks a local-development fixture against its expected participant index.
    ///
    /// This check does not authenticate the fixture against genesis or a ceremony transcript.
    ValidateFixture {
        /// File containing the storage-key fixture bundle.
        #[arg(long, value_name = "FILE")]
        bundle_file: PathBuf,

        /// DKG participant index that must own the secret share.
        #[arg(long, value_name = "NUM")]
        expected_participant: u32,
    },
}

/// Inputs for participating in a live peer-to-peer DKG ceremony.
#[derive(clap::Args)]
struct ParticipateOptions {
    /// File that receives this validator's storage-key bundle. The parent directory must exist, and
    /// the file must not already exist.
    #[arg(long, value_name = "FILE")]
    output_file: PathBuf,

    /// File containing this validator's persistent peer-to-peer endpoint secret.
    ///
    /// Reusing this secret keeps the advertised endpoint ID stable across ceremonies.
    #[arg(long, value_name = "FILE")]
    endpoint_secret: PathBuf,

    /// Enables n0's public Iroh relays and address discovery.
    ///
    /// Without this flag, peers connect directly using the supplied socket addresses.
    #[arg(long)]
    enable_public_relay: bool,

    /// Local UDP listening address. Direct-mode participants that accept peers require a nonzero
    /// port. Other participants default to randomly assigned ports on all interfaces.
    #[arg(long, value_name = "IP:PORT")]
    bind_address: Option<SocketAddr>,

    /// Trusted validator public key and peer-to-peer endpoint. Repeat once per other validator.
    ///
    /// Append @IP:PORT for direct connections. A socket address is required unless public relays
    /// are enabled. Each endpoint must prove ownership of its paired validator key.
    #[arg(long = "peer", num_args = 2, value_names = ["PUBLIC_KEY", "ENDPOINT_ID[@IP:PORT]"])]
    peers: Vec<String>,

    /// Maximum duration of peer authentication and all subsequent ceremony steps.
    #[arg(long, value_name = "DURATION", default_value = "30m", value_parser = humantime::parse_duration)]
    timeout: Duration,

    /// Number of shares needed to decrypt a private record.
    #[arg(long, value_name = "NUM")]
    threshold: NonZeroUsize,

    /// Hex-encoded 32-byte storage-key epoch.
    #[arg(long, value_name = "HEX")]
    epoch: String,

    /// This validator's signing key.
    #[command(flatten)]
    signing_key: ValidatorSigningKey,
}

impl DkgOptions {
    /// Handles one peer-to-peer DKG command.
    pub async fn handle(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        match self.command {
            DkgCommand::GenerateEndpoint { output_file } => {
                let secret_key = IrohSecretKey::generate();
                let secret_key_bytes = Zeroizing::new(secret_key.to_bytes());
                let mut options = fs_err::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use fs_err::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = options.open(&output_file).with_context(|| {
                    format!("failed to create Iroh endpoint secret {}", output_file.display())
                })?;
                file.write_all(secret_key_bytes.as_slice()).with_context(|| {
                    format!("failed to write Iroh endpoint secret {}", output_file.display())
                })?;
                println!("Iroh endpoint ID: {}", secret_key.public());
                Ok(())
            },
            DkgCommand::Participate(options) => Box::pin(options.handle(shutdown)).await,
            DkgCommand::ValidateFixture { bundle_file, expected_participant } => {
                let expected_participant = ParticipantIndex::new(expected_participant)?;
                let operator_key = ValidatorStorageKey { file: bundle_file }.load()?;
                ensure!(
                    operator_key.participant() == expected_participant,
                    "fixture belongs to participant {}, expected {}",
                    operator_key.participant().get(),
                    expected_participant.get(),
                );
                println!(
                    "Storage key fixture is valid for participant {}.",
                    expected_participant.get()
                );
                Ok(())
            },
        }
    }
}

impl ParticipateOptions {
    /// Parses a peer identity and its optional direct UDP address.
    fn parse_peer_endpoint(value: &str) -> anyhow::Result<EndpointAddr> {
        let (id, socket) = match value.split_once('@') {
            Some((id, socket)) => (id, Some(socket)),
            None => (value, None),
        };
        let id: EndpointId = id.parse().context("invalid peer endpoint ID")?;
        let mut endpoint = EndpointAddr::new(id);
        if let Some(socket) = socket {
            let socket: SocketAddr = socket.parse().context("invalid peer socket address")?;
            ensure!(
                socket.port() != 0 && !socket.ip().is_unspecified() && !socket.ip().is_multicast(),
                "peer socket address must have a unicast IP and a nonzero port",
            );
            endpoint = endpoint.with_ip_addr(socket);
        }
        Ok(endpoint)
    }

    /// Runs one ceremony attempt and closes the endpoint on success, error, timeout, or cancellation.
    ///
    /// Attempt state is not saved for resumption. A single validator follows the same steps with
    /// no peer exchanges, so it still generates and persists a one-of-one storage key.
    async fn handle(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let timeout = self.timeout;
        let output_file = self.output_file.clone();
        let parent = output_file
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        ensure!(
            fs_err::metadata(parent)?.is_dir(),
            "storage key output parent is not a directory: {}",
            parent.display(),
        );
        ensure!(
            !output_file.fs_err_try_exists()?,
            "storage key bundle already exists: {}",
            output_file.display(),
        );
        let (ceremony, endpoint) = tokio::select! {
            biased;
            () = shutdown.cancelled() => anyhow::bail!("DKG ceremony cancelled"),
            result = async {
                let ceremony = self.validate().await?;
                let endpoint = ceremony.bind_endpoint().await?;
                Ok::<_, anyhow::Error>((ceremony, endpoint))
            } => result?,
        };
        let attempt = tokio::time::timeout(timeout, async {
            let peers = ceremony.authenticate_peers(&endpoint).await?;
            let peers = ceremony.exchange_configs(peers).await?;
            let session = ceremony.exchange_nonces(peers).await?;
            let session = ceremony.confirm_session(session).await?;
            info!(
                target: miden_validator::LOG_TARGET,
                "DKG peer session established",
                dkg.session_id = session.id().to_string() #[nonstandard]
            );
            let participants = ceremony.exchange_dkg_public_keys(session).await?;
            let mut participants = ceremony.confirm_dkg_registry(participants).await?;
            info!(
                target: miden_validator::LOG_TARGET,
                "DKG participant registry established",
                dkg.local_index = participants.local_index().get() #[nonstandard],
                dkg.registry_root = hex::encode(participants.registry_root()) #[nonstandard]
            );

            let dealings = ceremony.create_dealings(&participants)?;
            info!(
                target: miden_validator::LOG_TARGET,
                "Local DKG dealings created",
                dkg.decryption_dealing_root = hex::encode(dealings.decryption_dealing_root()) #[nonstandard],
                dkg.context_dealing_root = hex::encode(dealings.context_dealing_root()) #[nonstandard]
            );

            let dealings = ceremony.exchange_dealings(&mut participants, dealings).await?;
            let dealings = ceremony.confirm_dealings(&mut participants, dealings).await?;
            info!(
                target: miden_validator::LOG_TARGET,
                "DKG dealings verified and confirmed with every peer",
                dkg.decryption_dealings = dealings.decryption_dealing_count() #[nonstandard],
                dkg.context_dealings = dealings.context_dealing_count() #[nonstandard],
                dkg.dealings_commitment = dealings.commitment().to_string() #[nonstandard]
            );

            let dealings_commitment = dealings.commitment();
            let output = ceremony.complete_dkg(&participants, dealings)?;
            info!(
                target: miden_validator::LOG_TARGET,
                "Local DKG key material derived",
                dkg.local_index = output.secret_share.participant.get() #[nonstandard],
                dkg.setup_context_root = hex::encode(output.setup_context.root()) #[nonstandard]
            );
            let completion = Completion::new(&participants, dealings_commitment, &output);
            // Save the local bundle before announcing completion to peers.
            //
            // A file on disk is not proof of ceremony success. If peer confirmation fails, the
            // bundle remains on disk but must not be used.
            ceremony.persist(&output_file, output)?;
            info!(
                target: miden_validator::LOG_TARGET,
                "Local storage key bundle written",
                dkg.storage_key_file = output_file #[nonstandard]
            );
            ceremony
                .confirm_completion(&mut participants, completion)
                .await
                .context("local bundle was written, but peer completion was not confirmed")?;
            info!(
                target: miden_validator::LOG_TARGET,
                "Every validator confirmed storage key bundle persistence"
            );
            Ok::<_, anyhow::Error>(())
        });
        let result = tokio::select! {
            biased;
            () = shutdown.cancelled() => Err(anyhow::anyhow!("DKG ceremony cancelled")),
            result = attempt => result.with_context(|| {
                format!("DKG ceremony timed out after {}", humantime::format_duration(timeout))
            }).and_then(|result| result),
        };

        endpoint.close().await;
        result
    }
}
