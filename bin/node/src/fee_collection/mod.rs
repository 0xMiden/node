use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_node_proto::clients::RemoteProverClient;
use miden_node_store::State;
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_node_tracing::{info, miden_instrument, miden_span_record};
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::Word;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::{Account, AccountFile, StorageSlotType};
use miden_protocol::block::BlockNumber;
use miden_standards::account::auth::AuthSingleSig;
use miden_standards::account::wallets::BasicWallet;

use crate::LOG_TARGET;

mod rpc;
mod store;
#[cfg(test)]
mod tests;
mod transaction;
pub(crate) use rpc::CollectionRpc;
use transaction::execute;

pub(crate) const DEFAULT_WALLET_SYNC_INTERVAL: Duration = Duration::from_mins(5);
pub(crate) const EXPIRATION_BLOCKS: u16 = 30;

pub(crate) struct FeeCollector {
    state: Arc<State>,
    rpc: CollectionRpc,
    prover: RemoteProverClient,
    account_template: Account,
    keys: Vec<AuthSecretKey>,
}

impl FeeCollector {
    pub(crate) fn new(
        state: Arc<State>,
        rpc: CollectionRpc,
        prover: RemoteProverClient,
        account: AccountFile,
    ) -> anyhow::Result<Self> {
        validate_account(&account.account, &account.auth_secret_keys)?;
        Ok(Self {
            state,
            rpc,
            prover,
            account_template: account.account,
            keys: account.auth_secret_keys,
        })
    }

    pub(crate) async fn run(
        self,
        interval: Duration,
        shutdown: CancellationToken,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(!interval.is_zero(), "fee collection interval must be greater than zero");
        let mut committed_tip = self.state.subscribe_committed_tip();
        let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => return Ok(()),
                _ = ticks.tick() => {},
            }
            let result = tokio::select! {
                biased;
                _ = shutdown.cancelled() => return Ok(()),
                result = self.collect_fees() => result,
            };
            let Some(expiration_block) = result.unwrap_or_else(|error| error.expiration_block)
            else {
                continue;
            };

            // A submitted transaction can still be dropped. Wait for its expiration.
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => return Ok(()),
                result = committed_tip.wait_for(|tip| *tip >= expiration_block) => {
                    result.context("committed chain tip subscription closed")?;
                },
            }
        }
    }

    /// Collects unspent fee payments and returns the transaction's expiration block.
    /// Returns `None` if no payments are available.
    ///
    /// Submission errors include the expiration block. The node can accept a
    /// transaction before submission reports an error. The caller must wait until the chain tip
    /// reaches the expiration block after either submission outcome.
    /// Errors from state loading, execution, and proving do not include an expiration block.
    #[miden_instrument(
        target = LOG_TARGET,
        name = "fee_collection.collect_fees",
        fields(account.id = self.account_template.id()),
        err,
    )]
    async fn collect_fees(&self) -> Result<Option<BlockNumber>, CollectionError> {
        let (context, notes) = self.collection_inputs().await?;
        miden_span_record!(
            reference_block.number = context.block_header.block_num(),
            note.count = notes.len()
        );
        if notes.is_empty() {
            info!(target: LOG_TARGET, "Skipping batch fee collection: no unspent payments");
            return Ok(None);
        }

        let keys = self.keys.clone();
        let runtime = tokio::runtime::Handle::current();
        let inputs = spawn_blocking_in_current_span(move || {
            let executed = runtime.block_on(Box::pin(execute(context, notes, &keys)))?;
            anyhow::Ok(executed.tx_inputs().clone())
        })
        .await
        .context("fee collection transaction task failed")??;
        let transaction = transaction::prove(&self.prover, &inputs).await?;

        let expiration_block = transaction.expiration_block_num();
        miden_span_record!(
            transaction.id = transaction.id(),
            transaction.expires_at = expiration_block
        );
        self.rpc.submit(&transaction, &inputs).await.map_err(|source| CollectionError {
            source,
            expiration_block: Some(expiration_block),
        })?;
        info!(target: LOG_TARGET, "Submitted batch fee collection transaction");
        Ok(Some(expiration_block))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("batch fee collection failed")]
struct CollectionError {
    #[source]
    source: anyhow::Error,
    expiration_block: Option<BlockNumber>,
}

impl From<anyhow::Error> for CollectionError {
    fn from(source: anyhow::Error) -> Self {
        Self { source, expiration_block: None }
    }
}

fn validate_account(account: &Account, keys: &[AuthSecretKey]) -> anyhow::Result<()> {
    anyhow::ensure!(
        account.is_public() && !account.is_new(),
        "batch builder must be a deployed public wallet"
    );
    anyhow::ensure!(
        account
            .storage()
            .slots()
            .iter()
            .all(|slot| slot.content().slot_type() == StorageSlotType::Value),
        "batch builder wallet must not use storage maps",
    );
    anyhow::ensure!(
        account.code().procedures().first()
            == AuthSingleSig::code().procedure_roots().next().as_ref()
            && account.code().has_procedure(BasicWallet::receive_asset_root().as_word()),
        "batch builder must use AuthSingleSig and BasicWallet",
    );
    let public_key = account.storage().get_item(AuthSingleSig::public_key_slot())?;
    let scheme = account.storage().get_item(AuthSingleSig::scheme_id_slot())?;
    anyhow::ensure!(
        keys.iter().any(|key| {
            Word::from(key.public_key().to_commitment()) == public_key
                && Word::from([key.auth_scheme().as_u8(), 0, 0, 0]) == scheme
        }),
        "batch builder account file must contain its signing key"
    );
    Ok(())
}
