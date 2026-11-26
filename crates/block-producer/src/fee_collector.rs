use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use miden_node_store::state::{BlockWriter, ProofWriter, State};
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_node_tracing::{info, instrument, miden_span_record};
use miden_objects::account_file::AccountFile;
use miden_protocol::account::Account;
use miden_protocol::batch::ProposedBatch;
use miden_protocol::{MIN_PROOF_SECURITY_LEVEL, ONE};
use url::Url;

use crate::batch_builder::BatchProver;
use crate::block_builder::{BlockBuilder, SelectedBlock};
use crate::block_prover::BlockProver;
use crate::store::{ChainInputs, read_chain_inputs, read_fee_collection_inputs};
use crate::validator::BlockProducerValidatorClient;

#[cfg(test)]
mod tests;

mod transaction;
pub(crate) use transaction::FeeCollectorTransactionBuilder;

mod faucet;

/// Deploys a new collector in one block and proves the transaction, batch, and block locally.
///
/// The deployment requires no funds and pays no fee. The sequencer must be stopped.
/// Returns without creating a block if the matching collector is already deployed.
#[instrument(name = "deploy_fee_collector", err)]
pub async fn deploy_fee_collector(
    state: &State,
    block_writer: &mut BlockWriter,
    proof_writer: &mut ProofWriter,
    account_file: AccountFile,
    validator_urls: Vec<Url>,
    validator_timeout: Duration,
    max_decoding_message_size: usize,
) -> anyhow::Result<()> {
    miden_span_record!(account.id = account_file.account().id());
    anyhow::ensure!(
        account_file.account().is_new(),
        "fee collector deployment requires a new account",
    );
    anyhow::ensure!(
        state.proven_tip() == state.committed_tip(),
        "sync all committed block proofs before deploying a fee collector",
    );
    let mut deployed_account = account_file.account().clone();
    deployed_account.set_nonce(ONE)?;
    if collector_is_deployed(state, &deployed_account).await? {
        info!("Fee collector is already deployed");
        return Ok(());
    }
    // Deployment creates no output note, so the recipient is not used.
    let builder =
        FeeCollectorTransactionBuilder::new(account_file.account().id(), account_file, state)
            .await?;
    let validator = BlockProducerValidatorClient::new(
        validator_urls,
        validator_timeout,
        max_decoding_message_size,
    )?;

    let fee_faucet = builder.fee_faucet().clone();
    let (inputs, config, genesis, fee_faucet_inputs) = state
        .read(move |view| {
            let reference_block = view.snapshot.block_num;
            let inputs =
                read_chain_inputs(&view, reference_block, BTreeSet::new(), &BTreeSet::new())?;
            let (config, genesis) =
                read_fee_collection_inputs(&view, &inputs.reference_block_header)?;
            let fee_faucet_inputs = fee_faucet.account_inputs(&view, reference_block)?;
            anyhow::Ok((inputs, config, genesis, fee_faucet_inputs))
        })
        .await?;
    let ChainInputs {
        reference_block_header: header,
        partial_blockchain: blockchain,
        ..
    } = inputs;
    let executed = builder
        .execute(Vec::new(), header.clone(), config, blockchain.clone(), fee_faucet_inputs, state)
        .await?;
    let inputs = executed.tx_inputs().clone();
    let transaction =
        spawn_blocking_in_current_span(move || FeeCollectorTransactionBuilder::prove(executed))
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
    let proof = BatchProver::new().prove(batch).await?;
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
    info!("Deployed batch builder collection account", block.number = block_number);
    Ok(())
}

/// Checks the collector's committed state and loads its deployed nonce.
pub(crate) async fn load_deployed_collector(
    state: &State,
    account_file: AccountFile,
) -> anyhow::Result<AccountFile> {
    let (mut account, auth_secret_keys) = account_file.into_parts();
    account.set_nonce(ONE)?;
    anyhow::ensure!(
        collector_is_deployed(state, &account).await?,
        "fee collector is not deployed; use miden-node fee-collector deploy",
    );
    Ok(AccountFile::new(account, auth_secret_keys))
}

async fn collector_is_deployed(state: &State, account: &Account) -> anyhow::Result<bool> {
    let id = account.id();
    let commitment = state
        .read(move |view| anyhow::Ok(view.snapshot.account_tree.get_latest_commitment(id)))
        .await?;
    if commitment.is_empty() {
        return Ok(false);
    }
    anyhow::ensure!(
        commitment == account.to_commitment(),
        "fee collector account file does not match the deployed account",
    );
    Ok(true)
}
