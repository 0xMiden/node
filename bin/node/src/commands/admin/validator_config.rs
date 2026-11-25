use std::path::PathBuf;

use anyhow::Context;

use crate::admin::AdminClient;

#[derive(clap::Args, Debug)]
pub(super) struct ValidatorConfigCommand {
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(clap::Subcommand, Debug)]
enum ConfigCommand {
    /// Print the active and pending quorums and activation height as JSON.
    Status,
    /// Schedule a validator quorum change.
    Register(ChangeFile),
    /// Cancel the change registered with this file and activation height.
    Cancel(ChangeFile),
}

#[derive(clap::Args, Debug)]
struct ChangeFile {
    /// JSON file containing the active and pending quorum values.
    file: PathBuf,

    /// First block signed under the new quorum.
    #[arg(long, value_name = "HEIGHT", value_parser = clap::value_parser!(u32).range(2..))]
    activation_height: u32,
}

impl ValidatorConfigCommand {
    pub(super) async fn handle(self, client: &AdminClient) -> anyhow::Result<()> {
        match self.command {
            ConfigCommand::Status => {
                let status = client.validator_config_status().await?;
                println!("{}", serde_json::to_string_pretty(&status)?);
            },
            ConfigCommand::Register(change) => {
                let body =
                    fs_err::read(change.file).context("failed to read quorum change file")?;
                client.register_validator_config(body, change.activation_height).await?;
                println!("Scheduled the validator quorum for block {}.", change.activation_height);
            },
            ConfigCommand::Cancel(change) => {
                let body =
                    fs_err::read(change.file).context("failed to read quorum change file")?;
                client.cancel_validator_config(body, change.activation_height).await?;
                println!(
                    "Cancelled the validator quorum change for block {}.",
                    change.activation_height
                );
            },
        }
        Ok(())
    }
}
