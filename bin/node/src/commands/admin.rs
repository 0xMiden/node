use std::collections::BTreeSet;
use std::io::{BufWriter, Write};
use std::num::NonZeroUsize;
use std::path::PathBuf;

use anyhow::Context;
use miden_protocol::account::AccountId;
use rand::distr::{Alphanumeric, SampleString};
use url::Url;

use crate::admin::AdminClient;

#[cfg(test)]
mod tests;

const INVITATION_CODE_LENGTH: usize = 12;

#[derive(clap::Args, Debug)]
pub struct AdminCommand {
    /// Base URL of the sequencer's private admin API.
    #[arg(long, env = "MIDEN_NODE_ADMIN_URL", value_name = "URL")]
    url: Url,

    #[command(subcommand)]
    action: AdminAction,
}

#[derive(clap::Subcommand, Debug)]
enum AdminAction {
    /// Create invitation codes and write the original codes to a new CSV file.
    CreateInvites(CreateInvitesCommand),
    /// Allowlist an account without an invitation code.
    AllowlistAccount {
        /// Hexadecimal account ID to allowlist.
        #[arg(value_name = "ACCOUNT_ID", value_parser = AccountId::from_hex)]
        account_id: AccountId,
    },
}

impl AdminCommand {
    pub async fn handle(self) -> anyhow::Result<()> {
        let client = AdminClient::new(self.url)?;
        match self.action {
            AdminAction::CreateInvites(command) => command.handle(&client).await,
            AdminAction::AllowlistAccount { account_id } => {
                client.allowlist_account(account_id).await?;
                println!("Allowlisted account {}.", account_id.to_hex());
                Ok(())
            },
        }
    }
}

#[derive(clap::Args, Debug)]
struct CreateInvitesCommand {
    /// Number of unique invitation codes to create.
    #[arg(long, value_name = "N")]
    count: NonZeroUsize,

    /// New CSV file for the invitation codes. The file must not exist.
    #[arg(long, value_name = "FILE")]
    output: PathBuf,
}

impl CreateInvitesCommand {
    async fn handle(self, client: &AdminClient) -> anyhow::Result<()> {
        // Save every code before the first request. An interrupted upload must not lose active
        // codes.
        let codes = self.save_codes()?;
        for (index, code) in codes.iter().enumerate() {
            client.create_invitation(code).await.with_context(|| {
                format!(
                    "failed to upload invitation {} of {}; CSV retained at {}",
                    index + 1,
                    self.count,
                    self.output.display()
                )
            })?;
        }
        println!("Created {} invitation codes in {}.", self.count, self.output.display());
        Ok(())
    }

    fn save_codes(&self) -> anyhow::Result<BTreeSet<String>> {
        let mut options = fs_err::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use fs_err::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&self.output).context("failed to create invitation CSV")?;
        let mut codes = BTreeSet::new();
        let mut rng = rand::rng();
        while codes.len() < self.count.get() {
            codes.insert(Alphanumeric.sample_string(&mut rng, INVITATION_CODE_LENGTH));
        }

        let mut writer = BufWriter::new(file);
        writeln!(writer, "invitation_code").context("failed to write CSV header")?;
        for code in &codes {
            writeln!(writer, "{code}").context("failed to write invitation CSV")?;
        }
        writer.flush().context("failed to flush invitation CSV")?;
        writer.get_ref().sync_all().context("failed to sync invitation CSV")?;
        Ok(codes)
    }
}
