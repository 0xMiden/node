use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_node_proto::domain::account::AccountRequest;
use miden_node_store::state::{BlockWriter, ProofWriter, State};
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_node_tracing::{info, miden_instrument, miden_span_record};
use miden_protocol::account::{Account, AccountFile};
use miden_protocol::batch::ProposedBatch;
use miden_protocol::block::BlockNumber;
use miden_protocol::{MIN_PROOF_SECURITY_LEVEL, ONE};
use url::Url;

use crate::batch_builder::BatchProver;
use crate::block_builder::{BlockBuilder, SelectedBlock};
use crate::block_prover::BlockProver;
use crate::validator::BlockProducerValidatorClient;
use crate::{COMPONENT, LOG_TARGET};

#[cfg(test)]
mod tests;

mod transaction;
pub(crate) use transaction::PassThroughTransactionBuilder;

/// Deploys a new collector in one block and proves the transaction, batch, and block locally.
///
/// The deployment requires no funds and pays no fee. The sequencer must be stopped.
/// Returns without creating a block if the matching collector is already deployed.
#[miden_instrument(target = COMPONENT, name = "deploy_fee_collector", err)]
pub async fn deploy_fee_collector(
    state: &State,
    block_writer: &mut BlockWriter,
    proof_writer: &mut ProofWriter,
    account_file: AccountFile,
    validator_urls: Vec<Url>,
    validator_timeout: Duration,
) -> anyhow::Result<()> {
    miden_span_record!(account.id = account_file.account.id());
    anyhow::ensure!(
        account_file.account.is_new(),
        "fee collector deployment requires a new account",
    );
    anyhow::ensure!(
        state.proven_tip() == state.committed_tip(),
        "sync all committed block proofs before deploying a fee collector",
    );
    let mut deployed_account = account_file.account.clone();
    deployed_account.set_nonce(ONE)?;
    if collector_is_deployed(state, &deployed_account).await? {
        info!(target: LOG_TARGET, "Fee collector is already deployed");
        return Ok(());
    }
    // Deployment creates no output note, so the recipient is not used.
    let builder = PassThroughTransactionBuilder::new(account_file.account.id(), account_file)?;
    let validator = BlockProducerValidatorClient::new(validator_urls, validator_timeout)?;

    let (header, config, blockchain, genesis) = state
        .with_view(async |view| {
            let tip = *view.tip();
            let (_, header, _) = view.sync_chain_mmr(tip..=tip).await?;
            let config = view
                .get_protocol_config(header.protocol_config_commitment())
                .await?
                .context("protocol configuration is missing")?;
            let blockchain = view.get_block_inclusion_proofs(tip, BTreeSet::new()).await?;
            let genesis = view
                .get_block_header(Some(BlockNumber::GENESIS), false)
                .await?
                .0
                .context("genesis block header is missing")?
                .commitment();
            anyhow::Ok((header, config, blockchain, genesis))
        })
        .await?;
    let executed = builder.execute(Vec::new(), header.clone(), config, blockchain.clone()).await?;
    let inputs = executed.tx_inputs().clone();
    let transaction =
        spawn_blocking_in_current_span(move || PassThroughTransactionBuilder::prove(executed))
            .await??;
    miden_span_record!(transaction.id = transaction.id());
    validator
        .validate_transaction(&transaction, &inputs, genesis, header.validator_config())
        .await?;
    let block_number = header.block_num().child();
    let batch = ProposedBatch::new(
        vec![Arc::new(transaction)],
        header,
        blockchain,
        BTreeMap::new(),
        MIN_PROOF_SECURITY_LEVEL,
    )?;
    let proof = BatchProver::local().prove(batch).await?;
    let block = BlockBuilder::prepare_block(
        state,
        &validator,
        SelectedBlock {
            block_number,
            batches: vec![Arc::new(proof)],
        },
    )
    .await?;
    let proof = BlockProver::local()
        .prove(
            block.ordered_batches.clone(),
            block.block_inputs.clone(),
            block.signed_block.header(),
        )
        .await?;
    block_writer
        .apply_block_with_proving_inputs(
            block.ordered_batches,
            block.block_inputs,
            block.signed_block,
        )
        .await?;
    proof_writer.apply_proof(block_number, proof.to_bytes()).await?;
    info!(target: LOG_TARGET, "Deployed batch builder collection account", block.number = block_number);
    Ok(())
}

async fn collector_is_deployed(state: &State, account: &Account) -> anyhow::Result<bool> {
    let response = state
        .view()
        .get_account(AccountRequest {
            account_id: account.id(),
            block_num: None,
            details: None,
        })
        .await?;
    if response.witness.state_commitment().is_empty() {
        return Ok(false);
    }
    anyhow::ensure!(
        response.witness.state_commitment() == account.to_commitment(),
        "fee collector account file does not match the deployed account",
    );
    Ok(true)
}
