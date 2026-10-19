use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_node_proto::clients::{Builder, ValidatorClient};
use miden_node_proto::domain::protocol_config::ensure_protocol_config_is_present_and_matches_header;
use miden_node_proto::generated::miden::validator::v1::{
    BlockSubscriptionRequest,
    BlockSubscriptionResponse,
};
use miden_node_proto::{BlockProofRequest, DecodeMessageExt};
use miden_node_store::{BlockWriter, ProofWriter, State, WriterTask};
use miden_node_tracing::info;
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::Word;
use miden_protocol::block::{
    BlockBody,
    BlockHeader,
    BlockNumber,
    BlockSignatures,
    SignedBlock,
    ValidatorConfig,
};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::Signature;
use miden_protocol::protocol_config::ProtocolConfig;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_stream::StreamExt;
use tonic::codec::Streaming;
use url::Url;

use super::ENV_DATA_DIRECTORY;
use super::store::StoreOptions;
use crate::LOG_TARGET;

// RECOVER
// ================================================================================================

/// Capacity of the channels connecting the recovery pipeline's stages, bounding the number of
/// blocks buffered in memory while keeping every stage busy.
const BLOCK_CHANNEL_CAPACITY: usize = 16;

/// A recovered block with any protocol configuration and proving request supplied by validators.
#[derive(Debug)]
struct RecoveredBlock {
    block: SignedBlock,
    protocol_config: Option<ProtocolConfig>,
    proving_inputs: Option<BlockProofRequest>,
}

/// Tracks the active protocol configuration commitment for one validator stream.
#[derive(Default)]
struct ProtocolConfigStreamState {
    commitment: Option<Word>,
}

impl ProtocolConfigStreamState {
    /// Accepts a stream event only if it supplies every required configuration payload.
    fn accept(&mut self, commitment: Word, supplied: bool) -> anyhow::Result<()> {
        match self.commitment {
            None if !supplied => anyhow::bail!("stream is missing its baseline protocol config"),
            Some(previous) if previous != commitment && !supplied => {
                anyhow::bail!("stream is missing its changed protocol config")
            },
            _ => {},
        }
        self.commitment = Some(commitment);
        Ok(())
    }
}

#[derive(clap::Args, Clone, Debug)]
pub struct RecoverCommand {
    /// Directory containing the node's local data storage.
    #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
    data_directory: PathBuf,

    /// The validator service gRPC URLs to recover blocks from.
    ///
    /// Repeat the flag once per validator. The URLs must cover the full validator set, since each
    /// validator's block backup carries only that validator's own signature and a block can only
    /// be reconstructed once the signatures of the whole set have been collected. The environment
    /// variable accepts a comma-separated list.
    #[arg(
        long = "validator.url",
        env = "MIDEN_NODE_VALIDATOR_URL",
        value_name = "URL",
        value_delimiter = ',',
        required = true
    )]
    validator_urls: Vec<Url>,

    /// Prove all committed blocks after restoring their inputs, without starting block production.
    #[arg(long)]
    prove: bool,

    #[command(flatten)]
    block_prover: super::block_producer::BlockProverOptions,

    #[command(flatten)]
    store: StoreOptions,
}

impl RecoverCommand {
    pub async fn handle(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let (state, mut block_writer, mut proof_writer, writer_task) = self.load_state().await?;
        let result = async {
            let validators = self
                .validator_urls
                .iter()
                .map(|url| Ok((url.clone(), Self::validator_client(url)?)))
                .collect::<anyhow::Result<Vec<_>>>()?;
            recover_from_validators(&state, &mut block_writer, validators, shutdown.clone())
                .await?;
            if self.prove {
                miden_node_block_producer::prove_pending_blocks(
                    &state,
                    &mut proof_writer,
                    self.block_prover.url,
                    shutdown,
                )
                .await?;
                info!(target: LOG_TARGET, "Recovery proving complete",
                    block.number = state.proven_tip(), tip.number = state.committed_tip());
            } else {
                info!(target: LOG_TARGET, "Recovered inputs are ready for proving",
                    block.number = state.proven_tip(), tip.number = state.committed_tip(),
                    sync.block_gap = state.committed_tip().as_u32() - state.proven_tip().as_u32());
            }
            Ok(())
        }
        .await;
        // Accepted writes finish before recovery returns, including on failure or shutdown.
        drop(proof_writer);
        block_writer.stop(writer_task).await;
        result
    }

    async fn load_state(
        &self,
    ) -> anyhow::Result<(Arc<State>, BlockWriter, ProofWriter, WriterTask)> {
        let loaded = State::load_with_database_options(
            &self.data_directory,
            self.store.storage.clone().into(),
            self.store.sqlite.database_options(),
        )
        .await
        .context("failed to load state")?;

        // The writer uses a separate cancellation token so recovery cancellation cannot interrupt
        // accepted writes.
        let (state, block_writer, proof_writer, writer_task) =
            loaded.start(CancellationToken::new());
        Ok((state, block_writer, proof_writer, writer_task))
    }

    fn validator_client(url: &Url) -> anyhow::Result<ValidatorClient> {
        Ok(Builder::new(url.clone())
            .with_tls()?
            .with_timeout(Duration::from_secs(5))
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<ValidatorClient>())
    }
}

/// Streams blocks from all validators into the local store until the recovery target is reached.
///
/// Each validator's block backup carries only that validator's own signature, so blocks are pulled
/// from every validator in lock-step and the individual signatures are coalesced into the full,
/// positionally ordered signature set before each block is applied.
async fn recover_from_validators(
    state: &State,
    block_writer: &mut BlockWriter,
    mut validators: Vec<(Url, ValidatorClient)>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    // The recovery target is the highest block for which every validator can supply a signature.
    //
    // Each backup stream captures a finite tip. The sequencer must remain stopped so the target
    // stays fixed while validator statuses are queried and backup streams are opened.
    let mut recovery_tip: Option<BlockNumber> = None;
    for (url, validator) in &mut validators {
        let response = tokio::select! {
            _ = shutdown.cancelled() => anyhow::bail!("recovery cancelled"),
            response = validator.status(miden_node_proto::generated::miden::validator::v1::StatusRequest {}) => response,
        };
        let tip = BlockNumber::from(
            response
                .with_context(|| format!("failed to query status of validator {url}"))?
                .into_inner()
                .chain_tip,
        );
        recovery_tip = Some(recovery_tip.map_or(tip, |current| current.min(tip)));
    }
    let recovery_tip = recovery_tip.context("at least one validator URL is required")?;

    let start = tokio::select! {
        _ = shutdown.cancelled() => anyhow::bail!("recovery cancelled"),
        start = inputs::recovery_start(state, recovery_tip) => start?,
    };
    let Some(start) = start else {
        info!(target: LOG_TARGET, "Local chain and proving inputs already cover recovery target",
            block.number = state.committed_tip(), sync.upstream_block = recovery_tip);
        return Ok(());
    };

    let mut tasks = JoinSet::new();
    let result: anyhow::Result<()> = async {
        Box::pin(run_recovery_pipeline(
            state,
            block_writer,
            validators,
            start,
            recovery_tip,
            &mut tasks,
            shutdown,
        ))
        .await
    }
    .await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}

/// Restores blocks and proving inputs through the target height with bounded buffering.
///
/// Recovery succeeds only after all producer tasks finish successfully and the target block has
/// been applied, so a closed channel cannot hide a producer failure.
async fn run_recovery_pipeline(
    state: &State,
    writer: &mut BlockWriter,
    validators: Vec<(Url, ValidatorClient)>,
    start: BlockNumber,
    target: BlockNumber,
    tasks: &mut JoinSet<anyhow::Result<()>>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let (parent, _) = state
        .view()
        .get_block_header(Some((start.as_u32() - 1).into()), false)
        .await
        .context("failed to load recovery parent")?;
    let parent = parent.context("recovery parent header not found")?;
    let block_from = start.as_u32();
    let block_count = u64::from(target.as_u32()) - u64::from(block_from) + 1;
    info!(target: LOG_TARGET, "Recovering blocks and proving inputs from validators",
        block.from = block_from, sync.upstream_block = target, validators.count = validators.len());

    let mut block_streams = Vec::with_capacity(validators.len());
    for (url, mut validator) in validators {
        let response = tokio::select! {
            _ = shutdown.cancelled() => anyhow::bail!("recovery cancelled"),
            response = validator.block_subscription(BlockSubscriptionRequest { block_from }) => response,
        };
        let stream = response
            .with_context(|| format!("failed to open block subscription on validator {url}"))?
            .into_inner();
        let (block_tx, block_rx) = mpsc::channel(BLOCK_CHANNEL_CAPACITY);
        tasks.spawn(read_blocks(url.clone(), stream, block_count, block_tx));
        block_streams.push((url, block_rx));
    }
    let (coalesced_tx, mut coalesced_rx) = mpsc::channel(BLOCK_CHANNEL_CAPACITY);
    tasks.spawn(coalesce_blocks(block_streams, parent, target, coalesced_tx));
    let mut last_delivered = None;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => anyhow::bail!("recovery cancelled"),
            joined = tasks.join_next(), if !tasks.is_empty() => {
                joined.context("recovery producer missing")?.context("recovery producer panicked")??;
            },
            recovered = coalesced_rx.recv() => {
                let Some(recovered) = recovered else { break };
                let height = recovered.block.header().block_num();
                inputs::apply_recovered(state, writer, recovered).await
                    .with_context(|| format!("failed to recover block {height}"))?;
                last_delivered = Some(height);
                info!(target: LOG_TARGET, "Recovered block and proving inputs", block.number = height);
            },
        }
    }
    while !tasks.is_empty() {
        tokio::select! {
            _ = shutdown.cancelled() => anyhow::bail!("recovery cancelled"),
            joined = tasks.join_next() => {
                joined.context("recovery producer missing")?.context("recovery producer panicked")??;
            },
        }
    }
    anyhow::ensure!(last_delivered == Some(target), "recovery stream ended before target {target}");
    info!(target: LOG_TARGET, "Block and proving input recovery complete", tip.number = target);
    Ok(())
}

/// Reads `block_count` blocks from a validator's subscription stream into `blocks`.
///
/// Runs as a background task so that blocks are received and deserialized concurrently with
/// signature coalescing and block application. An error is forwarded through the channel and ends
/// the task; the task also ends when the coalescer shuts down.
async fn read_blocks(
    url: Url,
    mut stream: Streaming<BlockSubscriptionResponse>,
    block_count: u64,
    blocks: mpsc::Sender<anyhow::Result<RecoveredBlock>>,
) -> anyhow::Result<()> {
    let mut config_state = ProtocolConfigStreamState::default();
    for _ in 0..block_count {
        let block = stream
            .next()
            .await
            .with_context(|| {
                format!("block stream of validator {url} ended before the recovery target")
            })
            .and_then(|result| {
                result.with_context(|| format!("block stream of validator {url} returned an error"))
            })
            .and_then(|event| {
                let block: SignedBlock = event
                    .block
                    .context("validator block stream response is missing block")?
                    // SAFETY: Each backup contains only one validator's signature. The coalescer
                    // assembles and verifies the full signature set against the trusted parent
                    // before the writer receives the block.
                    .decode_and_build_unchecked()
                    .with_context(|| format!("failed to build block from validator {url}"))?;
                let protocol_config = event
                    .protocol_config
                    .map(|config| {
                        ensure_protocol_config_is_present_and_matches_header(
                            Some(config),
                            block.header(),
                        )
                    })
                    .transpose()
                    .with_context(|| {
                        format!("failed to decode protocol config from validator {url}")
                    })?;
                config_state
                    .accept(block.header().protocol_config_commitment(), protocol_config.is_some())
                    .with_context(|| {
                        format!("invalid protocol config stream from validator {url}")
                    })?;
                let proving_inputs = event
                    .proving_inputs
                    .map(miden_node_proto::DecodeMessageExt::decode_and_build_unchecked)
                    .transpose()
                    .with_context(|| {
                        format!(
                            "invalid proving inputs from validator {url} for block {}",
                            block.header().block_num()
                        )
                    })?;
                Ok(RecoveredBlock { block, protocol_config, proving_inputs })
            });

        let is_err = block.is_err();
        if blocks.send(block).await.is_err() || is_err {
            return Ok(());
        }
    }
    Ok(())
}

/// Coalesces the per-validator block streams into fully signed, verified blocks and forwards them
/// in block-number order for application.
async fn coalesce_blocks(
    mut block_streams: Vec<(Url, mpsc::Receiver<anyhow::Result<RecoveredBlock>>)>,
    mut parent: BlockHeader,
    recovery_tip: BlockNumber,
    coalesced: mpsc::Sender<RecoveredBlock>,
) -> anyhow::Result<()> {
    for block_num in parent.block_num().child().as_u32()..=recovery_tip.as_u32() {
        let block = next_coalesced_block(&mut block_streams, &parent)
            .await
            .with_context(|| format!("failed to reconstruct block {block_num}"))?;
        parent = block.block.header().clone();

        // A send failure means the applier has shut down; its error is reported by the caller.
        if coalesced.send(block).await.is_err() {
            return Ok(());
        }
    }
    Ok(())
}

/// Pulls the next block from every validator stream and coalesces the validators' individual
/// signatures into a fully signed block, validated against the trusted `parent` header.
///
/// Every validator serves the same header and body for a committed block, but each backup carries
/// exactly one signature — the validator's own — and does not record which position in the
/// validator set that signature occupies. The signatures are therefore matched to their positions
/// by verifying them against the validator keys committed to by the parent header.
async fn next_coalesced_block(
    block_streams: &mut [(Url, mpsc::Receiver<anyhow::Result<RecoveredBlock>>)],
    parent: &BlockHeader,
) -> anyhow::Result<RecoveredBlock> {
    let expected_block_num = parent.block_num().child();

    let mut signatures = Vec::with_capacity(block_streams.len());
    let mut supplied_inputs = Vec::new();
    let mut first_parts: Option<(BlockHeader, BlockBody, Option<ProtocolConfig>)> = None;
    for (url, blocks) in block_streams.iter_mut() {
        let recovered = blocks
            .recv()
            .await
            .with_context(|| format!("block channel of validator {url} closed unexpectedly"))??;
        let RecoveredBlock { block, protocol_config, proving_inputs } = recovered;
        if let Some(request) = proving_inputs {
            supplied_inputs.push((url.clone(), request));
        }

        anyhow::ensure!(
            block.header().block_num() == expected_block_num,
            "validator {url} served block {} but block {expected_block_num} was expected",
            block.header().block_num(),
        );

        let (header, body, block_signatures) = block.into_parts();
        let signature = match block_signatures.as_signatures() {
            [signature] => signature.clone(),
            other => anyhow::bail!(
                "backup block of validator {url} carries {} signatures but exactly one (its own) was expected",
                other.len(),
            ),
        };

        match &first_parts {
            None => first_parts = Some((header, body, protocol_config)),
            Some((first_header, first_body, first_protocol_config)) => {
                anyhow::ensure!(
                    body == *first_body,
                    "validator {url} served a divergent body for block {expected_block_num}"
                );
                anyhow::ensure!(
                    header.commitment() == first_header.commitment(),
                    "validator {url} served a block with commitment {} which diverges from commitment {} served by the first validator",
                    header.commitment(),
                    first_header.commitment(),
                );
                anyhow::ensure!(
                    protocol_config == *first_protocol_config,
                    "validator {url} served a protocol config which diverges from the first validator",
                );
            },
        }
        signatures.push(signature);
    }
    let (header, body, protocol_config) =
        first_parts.context("at least one validator stream is required")?;

    let signatures =
        coalesce_signatures(signatures, header.commitment(), parent.validator_config())?;
    let block = SignedBlock::new_unchecked(header, body, signatures);

    // Fully validate the reconstructed block before it is persisted, including verifying the
    // signature set against the parent's validator keys; `BlockWriter::apply_block` does not verify
    // signatures.
    block.validate(Some(parent)).context("coalesced block failed validation")?;

    let mut proving_inputs = None;
    for (url, request) in supplied_inputs {
        request.validate_against(&block).with_context(|| {
            format!("invalid proving inputs from validator {url} for block {expected_block_num}")
        })?;
        if proving_inputs.is_none() {
            proving_inputs = Some(request);
        }
    }
    Ok(RecoveredBlock { block, protocol_config, proving_inputs })
}

/// Orders the collected per-validator signatures positionally against the validator set: the
/// signature in slot `i` must be produced by the validator key at index `i`.
///
/// A backup does not record which position its signature occupies, so each signature is matched to
/// its position by verifying it against the validator keys over the block commitment.
fn coalesce_signatures(
    mut signatures: Vec<Signature>,
    block_commitment: Word,
    validator_config: &ValidatorConfig,
) -> anyhow::Result<BlockSignatures> {
    anyhow::ensure!(
        signatures.len() == validator_config.len(),
        "collected {} signatures but the validator set has {} keys; the provided validator URLs \
         must cover the full validator set",
        signatures.len(),
        validator_config.len(),
    );

    let mut ordered = Vec::with_capacity(validator_config.len());
    for (position, key) in validator_config.keys().iter().enumerate() {
        let matched = signatures
            .iter()
            .position(|signature| signature.verify(block_commitment, key))
            .with_context(|| {
                format!(
                    "no unmatched signature verifies against the validator key at position \
                     {position}; the provided validator URLs must cover the full validator set"
                )
            })?;
        ordered.push(signatures.swap_remove(matched));
    }

    BlockSignatures::new(ordered).context("failed to construct the coalesced signature set")
}

mod inputs;

#[cfg(test)]
mod tests;
