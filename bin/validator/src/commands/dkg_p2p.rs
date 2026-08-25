use std::path::PathBuf;

use anyhow::Context;
use iroh_base::SecretKey as IrohSecretKey;
use zeroize::Zeroizing;

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
}

impl DkgP2pOptions {
    /// Handles one peer-to-peer DKG command.
    pub fn handle(self) -> anyhow::Result<()> {
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
        }
    }
}
