use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, ensure};
use fs_err::PathExt;
use iroh::{EndpointId, SecretKey as IrohSecretKey};
use miden_node_tracing::info;
use zeroize::Zeroizing;

use super::ValidatorSigningKey;

mod ceremony;
mod wire;

#[cfg(test)]
mod tests;

/// Inputs for one peer-to-peer DKG command.
#[derive(clap::Args)]
pub struct DkgP2pOptions {
    #[command(subcommand)]
    command: DkgP2pCommand,
}

/// Peer-to-peer DKG commands.
#[derive(clap::Subcommand)]
enum DkgP2pCommand {
    /// Generates this validator's persistent peer-to-peer endpoint identity.
    GenerateEndpoint {
        /// Output file for the peer-to-peer endpoint secret.
        #[arg(long, value_name = "FILE")]
        output_file: PathBuf,
    },

    /// Runs a live peer-to-peer DKG ceremony and writes this validator's storage-key bundle.
    Participate(ParticipateOptions),
}

/// Inputs for participating in a live peer-to-peer DKG ceremony.
#[derive(clap::Args)]
struct ParticipateOptions {
    /// File that receives this validator's storage-key bundle. The parent directory must exist, and
    /// the file must not already exist.
    #[arg(long, value_name = "FILE")]
    output_file: PathBuf,

    /// Trusted genesis block for the network.
    #[arg(long, value_name = "FILE")]
    genesis: PathBuf,

    /// File containing this validator's persistent peer-to-peer endpoint secret.
    ///
    /// Reusing this secret keeps the advertised endpoint ID stable across ceremonies.
    #[arg(long, value_name = "FILE")]
    endpoint_secret: PathBuf,

    /// Peer-to-peer endpoint of another validator. Repeat once per other genesis validator.
    ///
    /// These endpoints supply connection destinations, not trusted validator identities. Each
    /// peer must prove ownership of a genesis validator key during authentication.
    #[arg(long = "peer.endpoint", value_name = "ENDPOINT_ID")]
    peer_endpoints: Vec<EndpointId>,

    /// Maximum duration of peer authentication and all subsequent ceremony steps.
    #[arg(long, value_name = "DURATION", default_value = "30m", value_parser = humantime::parse_duration)]
    timeout: Duration,

    /// Number of shares needed to decrypt a private record.
    #[arg(long, value_name = "NUM")]
    threshold: NonZeroUsize,

    /// Hex-encoded 32-byte storage-key epoch.
    #[arg(long, value_name = "HEX")]
    epoch: String,

    /// Validator signing key committed by genesis.
    #[command(flatten)]
    signing_key: ValidatorSigningKey,
}

impl DkgP2pOptions {
    /// Handles one peer-to-peer DKG command.
    pub async fn handle(self) -> anyhow::Result<()> {
        match self.command {
            DkgP2pCommand::GenerateEndpoint { output_file } => {
                let secret_key = IrohSecretKey::generate();
                let secret_key_bytes = Zeroizing::new(secret_key.to_bytes());
                fs_err::write(&output_file, secret_key_bytes.as_slice()).with_context(|| {
                    format!("failed to write Iroh endpoint secret {}", output_file.display())
                })?;
                println!("Iroh endpoint ID: {}", secret_key.public());
                Ok(())
            },
            DkgP2pCommand::Participate(options) => Box::pin(options.handle()).await,
        }
    }
}

impl ParticipateOptions {
    async fn handle(self) -> anyhow::Result<()> {
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
        let ceremony = self.validate().await?;
        let endpoint = ceremony.bind_endpoint().await?;
        let result = tokio::time::timeout(timeout, async {
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

            let output = ceremony.complete_dkg(&participants, dealings)?;
            info!(
                target: miden_validator::LOG_TARGET,
                "Local DKG key material derived",
                dkg.local_index = output.secret_share.participant.get() #[nonstandard],
                dkg.setup_context_root = hex::encode(output.setup_context.root()) #[nonstandard]
            );
            ceremony.persist(&output_file, output)?;
            participants.finish_streams()?;
            info!(
                target: miden_validator::LOG_TARGET,
                "Local storage key bundle written",
                dkg.storage_key_file = output_file #[nonstandard]
            );
            Ok::<_, anyhow::Error>(())
        })
        .await
        .with_context(|| {
            format!("DKG ceremony timed out after {}", humantime::format_duration(timeout))
        });

        endpoint.close().await;
        result?
    }
}
