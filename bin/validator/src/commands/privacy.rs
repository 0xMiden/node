//! Storage-key ceremonies and private-record recovery commands.

use miden_node_utils::shutdown::CancellationToken;

/// Inputs for one privacy operation.
#[derive(clap::Args)]
pub struct PrivacyOptions {
    #[command(subcommand)]
    pub(super) command: PrivacyCommand,
}

/// Operations for establishing storage keys and recovering records.
#[derive(clap::Subcommand)]
pub(super) enum PrivacyCommand {
    /// Runs peer-to-peer storage-key setup commands.
    Dkg(super::dkg::DkgOptions),
    /// Exports records, issues shares, and recovers plaintext.
    Record(RecordOptions),
}

/// Inputs for one private-record operation.
#[derive(clap::Args)]
pub(super) struct RecordOptions {
    #[command(subcommand)]
    command: RecordCommand,
}

/// Offline operations on private-record bundles and shares.
#[derive(clap::Subcommand)]
enum RecordCommand {
    /// Exports one validator-qualified private-record bundle.
    Export(super::PrivateRecordExportOptions),
    /// Issues this validator's share for an exported record.
    IssueShare(super::PrivateRecordShareOptions),
    /// Combines collected shares and writes the authenticated plaintext.
    Decrypt(super::PrivateRecordDecryptOptions),
}

impl PrivacyOptions {
    pub(super) async fn handle(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        match self.command {
            PrivacyCommand::Dkg(options) => options.handle(shutdown).await,
            PrivacyCommand::Record(options) => match options.command {
                RecordCommand::Export(options) => {
                    super::export_private_record::export(options).await
                },
                RecordCommand::IssueShare(options) => {
                    super::issue_private_record_share::issue_from_options(options)
                },
                RecordCommand::Decrypt(options) => {
                    super::decrypt_private_record::decrypt_from_options(options)
                },
            },
        }
    }
}
