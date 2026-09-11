use std::num::NonZeroUsize;
use std::path::PathBuf;

use anyhow::Context;
use iroh::{EndpointId, SecretKey as IrohSecretKey};
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

    /// Participates in a live peer-to-peer DKG ceremony.
    Participate(ParticipateOptions),
}

/// Inputs for participating in a live peer-to-peer DKG ceremony.
#[derive(clap::Args)]
struct ParticipateOptions {
    /// Trusted genesis block for the network.
    #[arg(long, value_name = "FILE")]
    genesis: PathBuf,

    /// File containing this validator's persistent peer-to-peer endpoint secret.
    #[arg(long, value_name = "FILE")]
    endpoint_secret: PathBuf,

    /// Peer-to-peer endpoint of another validator. Repeat once per other genesis validator.
    #[arg(long = "peer.endpoint", value_name = "ENDPOINT_ID")]
    peer_endpoints: Vec<EndpointId>,

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
        let ceremony = self.validate().await?;
        let (endpoint, peers) = ceremony.authenticate_peers().await?;
        let peers = ceremony.exchange_configs(peers).await?;
        let session = ceremony.exchange_nonces(peers).await?;
        let session = ceremony.confirm_session(session).await?;
        tracing::info!(
            target: miden_validator::LOG_TARGET,
            { dkg.session_id = %session.id() },
            "DKG peer session established",
        );
        let participants = ceremony.exchange_dkg_public_keys(session).await?;
        let participants = ceremony.confirm_dkg_registry(participants).await?;
        tracing::info!(
            target: miden_validator::LOG_TARGET,
            {
                dkg.local_index = participants.local_index().get(),
                dkg.registry_root = %hex::encode(participants.registry_root()),
            },
            "DKG participant registry established",
        );

        let dealings = ceremony.create_dealings(&participants)?;
        tracing::info!(
            target: miden_validator::LOG_TARGET,
            {
                dkg.decryption_dealing_root = %hex::encode(dealings.decryption_dealing_root()),
                dkg.context_dealing_root = %hex::encode(dealings.context_dealing_root()),
            },
            "Local DKG dealings created",
        );

        let dealings = ceremony.exchange_dealings(&participants, dealings).await?;
        let dealings = ceremony.confirm_dealings(&participants, dealings).await?;
        tracing::info!(
            target: miden_validator::LOG_TARGET,
            {
                dkg.decryption_dealings = dealings.decryption_dealing_count(),
                dkg.context_dealings = dealings.context_dealing_count(),
                dkg.dealings_commitment = %dealings.commitment(),
            },
            "DKG dealings verified and confirmed with every peer",
        );

        let output = ceremony.complete_dkg(&participants, dealings)?;
        tracing::info!(
            target: miden_validator::LOG_TARGET,
            {
                dkg.local_index = output.secret_share.participant.get(),
                dkg.setup_context_root = %hex::encode(output.setup_context.root()),
            },
            "Local DKG key material derived",
        );

        endpoint.close().await;
        Ok(())
    }
}
