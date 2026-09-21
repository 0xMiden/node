use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use miden_node_block_producer::{DEFAULT_VALIDATOR_TIMEOUT, deploy_fee_collector};
use miden_node_store::{DataDirectory, State};
use miden_node_tracing::info;
use miden_node_utils::clap::duration_to_human_readable_string;
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::{AccountBuilder, AccountFile, AccountType};
use miden_protocol::utils::serde::Serializable;
use miden_standards::account::auth::AuthTxFeeCollector;
use miden_standards::account::wallets::BasicWallet;
use url::Url;

use super::ENV_DATA_DIRECTORY;
use super::store::StoreOptions;

#[cfg(test)]
mod tests;

#[derive(clap::Subcommand, Debug)]
pub enum FeeCollectorCommand {
    /// Create a fee collector account and save its signing key.
    ///
    /// Writes fee-collector.mac in the existing data directory. Refuses to overwrite an existing
    /// file. Creation is offline. Keep the file private because it contains the signing key.
    ///
    /// Use `miden-node fee-collector deploy` to deploy this account before starting the sequencer.
    Create(CreateCommand),

    /// Deploy a fee collector account in a dedicated block.
    ///
    /// Loads fee-collector.mac from the data directory, or the file specified by
    /// --fee-collector-account.
    ///
    /// Stop any node process that uses the data directory. All validators must be running to
    /// validate the transaction and sign the deployment block.
    ///
    /// Generates the transaction, batch, and block proofs locally. Deployment requires no funds
    /// and pays no transaction fee. If the matching account is already deployed, the command
    /// succeeds without creating another block.
    ///
    /// After deployment, start the sequencer with the same account file.
    Deploy(Box<DeployCommand>),
}

impl FeeCollectorCommand {
    pub async fn handle(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        match self {
            Self::Create(command) => command.handle(),
            Self::Deploy(command) => command.handle(shutdown).await,
        }
    }
}

#[derive(clap::Args, Debug)]
pub struct CreateCommand {
    /// Existing directory in which to create fee-collector.mac. The file must not exist.
    #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
    data_directory: PathBuf,
}

impl CreateCommand {
    fn handle(self) -> anyhow::Result<()> {
        let output = DataDirectory::load(self.data_directory)?.fee_collector_account_path();
        let secret_key = AuthSecretKey::new_ecdsa_k256_keccak();
        let account = AccountBuilder::new(rand::random())
            .account_type(AccountType::Public)
            .with_component(AuthTxFeeCollector::from_public_key(secret_key.public_key()))
            .with_component(BasicWallet)
            .build()?;
        let account_file = AccountFile::new(account, vec![secret_key]);
        let mut options = fs_err::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use fs_err::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file =
            options.open(&output).context("failed to create fee collector account file")?;
        file.write_all(&account_file.to_bytes())?;
        file.sync_all()?;
        info!(
            target: crate::LOG_TARGET,
            "Saved new fee collector account",
            account.id = account_file.account.id(),
            account.file = output.as_path()
        );
        Ok(())
    }
}

#[derive(clap::Args, Clone, Debug)]
pub struct FeeCollectorAccountOptions {
    /// Fee collector account file, including its signing key. Defaults to fee-collector.mac in the
    /// data directory.
    #[arg(
        long = "fee-collector-account",
        env = "MIDEN_NODE_FEE_COLLECTOR_ACCOUNT",
        value_name = "FILE"
    )]
    account: Option<PathBuf>,
}

impl FeeCollectorAccountOptions {
    pub fn read(&self, data_directory: &Path) -> anyhow::Result<AccountFile> {
        let path = match &self.account {
            Some(path) => path.clone(),
            None => DataDirectory::load(data_directory.to_path_buf())?.fee_collector_account_path(),
        };
        AccountFile::read(&path).with_context(|| {
            format!("failed to read fee collector account from {}", path.display())
        })
    }
}

#[derive(clap::Args, Debug)]
pub struct DeployCommand {
    /// Directory containing the node's local data storage.
    #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
    data_directory: PathBuf,

    #[command(flatten)]
    fee_collector: FeeCollectorAccountOptions,

    /// URLs of all validators in the current validator set. Repeat this option for each validator.
    #[arg(
        long = "validator.url",
        env = "MIDEN_NODE_VALIDATOR_URL",
        value_name = "URL",
        value_delimiter = ',',
        required = true
    )]
    validator_urls: Vec<Url>,

    /// Request timeout for calls to the validator services.
    #[arg(
        long = "validator.timeout",
        env = "MIDEN_NODE_VALIDATOR_TIMEOUT",
        default_value = duration_to_human_readable_string(DEFAULT_VALIDATOR_TIMEOUT),
        value_parser = humantime::parse_duration,
        value_name = "DURATION"
    )]
    validator_timeout: Duration,

    #[command(flatten)]
    store: StoreOptions,
}

impl DeployCommand {
    async fn handle(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let account = self.fee_collector.read(&self.data_directory)?;
        let loaded = State::load_with_database_options(
            &self.data_directory,
            self.store.storage.into(),
            self.store.sqlite.database_options(),
        )
        .await
        .context("failed to load node state")?;
        let (state, mut block_writer, mut proof_writer, writer_task) =
            loaded.start(CancellationToken::new());
        let result = async {
            anyhow::ensure!(
                state.proven_tip() == state.committed_tip(),
                "sync all committed block proofs before deploying a fee collector",
            );
            tokio::select! {
                () = shutdown.cancelled() => anyhow::bail!("fee collector deployment cancelled"),
                result = Box::pin(deploy_fee_collector(
                    &state,
                    &mut block_writer,
                    &mut proof_writer,
                    account,
                    self.validator_urls,
                    self.validator_timeout,
                )) => result,
            }
        }
        .await;
        block_writer.stop(writer_task).await;
        result
    }
}
