use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use anyhow::{Context, ensure};
use iroh_base::{EndpointId, SecretKey as IrohSecretKey};
use miden_node_store::genesis::GenesisBlock;
use miden_node_utils::genesis::read_genesis_block;
use zeroize::Zeroizing;

use super::ValidatorSigningKey;

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
    Participate {
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
    },
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
            DkgP2pCommand::Participate {
                genesis,
                endpoint_secret,
                peer_endpoints,
                threshold,
                epoch,
                signing_key,
            } => {
                let genesis = GenesisBlock::try_from(read_genesis_block(&genesis)?)
                    .context("failed to validate genesis block")?;
                let validator_keys = genesis.inner().header().validator_keys().as_keys();
                let validator_count = validator_keys.len();

                ensure!(
                    threshold.get() <= validator_count,
                    "threshold must not exceed the {validator_count} genesis validators, got {threshold}",
                );

                let epoch = hex::decode(epoch).context("failed to decode storage key epoch")?;
                let _: [u8; 32] = epoch.try_into().map_err(|epoch: Vec<u8>| {
                    anyhow::anyhow!("storage key epoch has {} bytes, expected 32", epoch.len(),)
                })?;

                let endpoint_secret_bytes =
                    Zeroizing::new(
                        fs_err::read(&endpoint_secret).with_context(|| {
                            format!(
                                "failed to read Iroh endpoint secret {}",
                                endpoint_secret.display(),
                            )
                        })?,
                    );
                let endpoint_secret = IrohSecretKey::try_from(endpoint_secret_bytes.as_slice())
                    .context("failed to decode Iroh endpoint secret")?;

                let expected_peer_count = validator_count.saturating_sub(1);
                ensure!(
                    peer_endpoints.len() == expected_peer_count,
                    "expected {expected_peer_count} peer endpoints for {validator_count} genesis validators, got {}",
                    peer_endpoints.len(),
                );
                let unique_peer_endpoints = peer_endpoints.iter().copied().collect::<BTreeSet<_>>();
                ensure!(
                    unique_peer_endpoints.len() == peer_endpoints.len(),
                    "peer endpoints contain duplicates",
                );
                ensure!(
                    !unique_peer_endpoints.contains(&endpoint_secret.public()),
                    "peer endpoints contain the local endpoint",
                );

                let signer = signing_key.into_signer().await?;
                ensure!(
                    validator_keys.contains(&signer.public_key()),
                    "validator signing key is not committed by genesis",
                );

                Ok(())
            },
        }
    }
}
