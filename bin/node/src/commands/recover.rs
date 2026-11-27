use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_node_proto::clients::{Builder, ValidatorClient};
use miden_node_proto::domain::protocol_config::ensure_protocol_config_is_present_and_matches_header;
use miden_node_proto::generated::miden::validator::v1::BlockSubscriptionResponse;
use miden_node_proto::{BlockProofRequest, DecodeMessageExt};
use miden_node_store::{BlockWriter, ProofWriter, State, WriterTask};
use miden_node_tracing::{info, warn};
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::Word;
use miden_protocol::block::{
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
use url::Url;

use super::ENV_DATA_DIRECTORY;
use super::store::StoreOptions;

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
    #[command(flatten)]
    grpc: miden_node_utils::clap::GrpcMessageSizeOptions,
    /// Directory containing the node's local data storage.
    #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
    data_directory: PathBuf,

    /// The validator service gRPC URLs to recover blocks from.
    ///
    /// Repeat for each backup source. Recovering a new block requires a quorum of signatures from the
    /// parent validator set and one matching proving request. The environment variable accepts
    /// a comma-separated list.
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
                .map(|url| {
                    Ok((
                        url.clone(),
                        Self::validator_client(url, self.grpc.max_decoding_message_size.get())?,
                    ))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            recover_from_validators(&state, &mut block_writer, validators, shutdown.clone())
                .await?;
            if self.prove {
                miden_node_block_producer::prove_pending_blocks(
                    &state,
                    &mut proof_writer,
                    self.block_prover.url,
                    self.grpc.max_decoding_message_size.get(),
                    shutdown,
                )
                .await?;
                info!(target: "miden::proving::blocks", "Recovery proving complete",
                    block.number = state.proven_tip(), tip.number = state.committed_tip());
            } else {
                info!(
                    "Recovered inputs are ready for proving",
                    block.number = state.proven_tip(),
                    tip.number = state.committed_tip(),
                    sync.block_gap = state.committed_tip().as_u32() - state.proven_tip().as_u32()
                );
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

    fn validator_client(
        url: &Url,
        max_decoding_message_size: usize,
    ) -> anyhow::Result<ValidatorClient> {
        Ok(Builder::new(url.clone())
            .max_decoding_message_size(max_decoding_message_size)
            .with_tls()?
            .with_timeout(Duration::from_secs(5))
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<ValidatorClient>())
    }
}

/// Restores the deepest verified chain available from the configured backups.
async fn recover_from_validators(
    state: &State,
    writer: &mut BlockWriter,
    validators: Vec<(Url, ValidatorClient)>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    tokio::select! {
        _ = shutdown.cancelled() => anyhow::bail!("recovery cancelled"),
        result = Box::pin(restore(state, writer, validators)) => result?,
    }
    let (tip, _) = state.view().get_block_header(Some(state.committed_tip()), false).await?;
    let tip = tip.context("missing recovered tip")?;
    info!(
        "Block and proving input recovery complete",
        tip.number = tip.block_num(),
        block.commitment = tip.commitment()
    );
    Ok(())
}

async fn restore(
    state: &State,
    writer: &mut BlockWriter,
    validators: Vec<(Url, ValidatorClient)>,
) -> anyhow::Result<()> {
    let (available, unknown) = sources::discover(validators).await?;
    let target = available.iter().map(|(_, _, tip)| *tip).max();
    let start = inputs::recovery_start(state, target.unwrap_or(0).into()).await;
    let first_unread =
        start.as_ref().ok().copied().flatten().map_or_else(
            || state.committed_tip().as_u32().saturating_add(1),
            |height| height.as_u32(),
        );
    for (url, error) in unknown {
        warn!(
            error,
            "Backup status unavailable",
            sync.block_source.endpoint = url.as_str(),
            block.from = first_unread
        );
    }
    let target = target.context("no usable validator backup status")?;
    let Some(start) = start? else { return Ok(()) };
    restore_range(state, writer, available, start, target).await
}

/// Repairs retained inputs and restores the highest recoverable continuation in the advertised
/// range.
async fn restore_range(
    state: &State,
    writer: &mut BlockWriter,
    available: Vec<(Url, ValidatorClient, u32)>,
    start: BlockNumber,
    target: u32,
) -> anyhow::Result<()> {
    let retained = state.committed_tip();
    let (parent, _) = state.view().get_block_header(Some(retained), false).await?;
    let parent = parent.context("missing recovery parent")?;
    let mut parents = BTreeMap::from([(parent.commitment(), parent)]);
    let mut workers = JoinSet::new();
    let mut streams = Vec::new();
    for (url, client, tip) in available {
        let (tx, rx) = mpsc::channel(BLOCK_CHANNEL_CAPACITY);
        workers.spawn(sources::read(client, url.clone(), start.as_u32(), tip, tx));
        streams.push((url, tip, rx));
    }
    let mut branches = branches::Branches::default();
    let mut progressed = false;
    for height in start.as_u32()..=target {
        let mut groups = BTreeMap::<_, Vec<_>>::new();
        for (url, tip, rx) in &mut streams {
            if height > *tip {
                continue;
            }
            match rx.recv().await.context("backup worker stopped unexpectedly")? {
                Ok(entry) => groups
                    .entry(entry.block.header().commitment())
                    .or_default()
                    .push((url.clone(), entry)),
                Err(error) => {
                    warn!(
                        error,
                        "Backup incomplete",
                        sync.block_source.endpoint = url.as_str(),
                        block.from = height
                    );
                    *tip = height - 1;
                },
            }
        }
        if height <= retained.as_u32() {
            inputs::repair_retained(state, writer, height.into(), groups).await?;
            progressed = true;
            continue;
        }
        let mut candidates = Vec::new();
        let mut only_partial_quorums = !groups.is_empty();
        for (id, entries) in groups {
            let header = entries[0].1.block.header();
            let Some(parent) = parents.get(&header.prev_block_commitment()) else {
                only_partial_quorums = false;
                continue;
            };
            match reconstruct(entries, parent) {
                Ok(candidate) => candidates.push(candidate),
                Err(error) => {
                    only_partial_quorums &= error
                        .downcast_ref::<InsufficientSignatures>()
                        .is_some_and(|e| e.actual > 0);
                    warn!(
                        error,
                        "Unrecoverable backup candidate",
                        block.number = height,
                        block.commitment = id
                    );
                },
            }
        }
        if candidates.is_empty() {
            anyhow::ensure!(
                progressed || only_partial_quorums,
                "no recoverable block at height {height}"
            );
            warn!("No recoverable continuation", block.number = height);
            break;
        }
        parents = candidates
            .iter()
            .map(|c| (c.block.header().commitment(), c.block.header().clone()))
            .collect();
        for selected in branches.advance(candidates).await? {
            selected.apply(state, writer).await?;
        }
        progressed = true;
    }
    for selected in branches.finish().await? {
        selected.apply(state, writer).await?;
    }
    Ok(())
}

fn decode_entry(
    event: BlockSubscriptionResponse,
    source: Option<&Url>,
) -> anyhow::Result<RecoveredBlock> {
    // SAFETY: Backups can carry partial signatures. The recovery reader authenticates the
    // reconstructed block against its parent before forwarding it to the writer.
    let block: SignedBlock =
        event.block.context("missing backup block")?.decode_and_build_unchecked()?;
    let protocol_config = event
        .protocol_config
        .map(|c| ensure_protocol_config_is_present_and_matches_header(Some(c), block.header()))
        .transpose()?;
    let proving_inputs = match event
        .proving_inputs
        .map(DecodeMessageExt::decode_and_build_unchecked)
        .transpose()
    {
        Err(error) if let Some(url) = source => {
            warn!(
                error,
                "Malformed backup proving inputs",
                sync.block_source.endpoint = url.as_str(),
                block.number = block.header().block_num()
            );
            None
        },
        result => result?,
    };
    Ok(RecoveredBlock { block, protocol_config, proving_inputs })
}

/// Assembles a candidate from backup copies and verifies it against its reachable parent.
fn reconstruct(
    entries: Vec<(Url, RecoveredBlock)>,
    parent: &BlockHeader,
) -> anyhow::Result<RecoveredBlock> {
    let mut signatures = Vec::new();
    let mut config = None;
    let mut payload = None;
    for (url, entry) in entries {
        let RecoveredBlock { block, protocol_config, proving_inputs } = entry;
        signatures.push((url.clone(), block.signatures().as_signatures().to_vec()));
        if let Some(supplied) = protocol_config {
            anyhow::ensure!(
                supplied.to_commitment() == block.header().protocol_config_commitment(),
                "validator {url} served a protocol config which diverges from the block header"
            );
            config = Some(supplied);
        }
        if let Some(request) = proving_inputs {
            match request.validate_against(&block) {
                Ok(()) => {
                    payload.get_or_insert((block, request));
                },
                Err(error) => warn!(
                    error,
                    "Invalid backup proving inputs",
                    sync.block_source.endpoint = url.as_str(),
                    block.number = block.header().block_num()
                ),
            }
        }
    }
    let (block, proving_inputs) =
        payload.context("no valid proving inputs for backup candidate")?;
    let (header, body, _) = block.into_parts();
    let signatures =
        coalesce_signatures(signatures, header.commitment(), parent.validator_config())?;
    let block = SignedBlock::new_unchecked(header, body, signatures);
    block.validate(Some(parent)).context("coalesced block failed validation")?;
    Ok(RecoveredBlock {
        block,
        protocol_config: config,
        proving_inputs: Some(proving_inputs),
    })
}

/// Collects one valid signature per authorized signer and checks the parent's quorum. Overlapping
/// backups may supply the same signer's signature more than once.
fn coalesce_signatures(
    signatures: Vec<(Url, Vec<Signature>)>,
    block_commitment: Word,
    validator_config: &ValidatorConfig,
) -> anyhow::Result<BlockSignatures> {
    let quorum = usize::from(validator_config.quorum());
    let mut distinct = BTreeMap::new();
    for (url, contributions) in signatures {
        for signature in contributions {
            if let Some(index) = validator_config
                .keys()
                .iter()
                .position(|key| signature.verify(block_commitment, key))
            {
                distinct.entry(index).or_insert(signature);
            } else {
                warn!(
                    "Invalid backup block signature",
                    sync.block_source.endpoint = url.as_str(),
                    block.commitment = block_commitment
                );
            }
        }
    }
    if distinct.len() < quorum {
        return Err(InsufficientSignatures {
            block_commitment,
            actual: distinct.len(),
            quorum,
        }
        .into());
    }
    Ok(BlockSignatures::new(distinct.into_values().take(quorum).collect())?)
}

#[derive(Debug, thiserror::Error)]
#[error(
    "only {actual} distinct validator signatures for block {block_commitment}, quorum requires {quorum}"
)]
struct InsufficientSignatures {
    block_commitment: Word,
    actual: usize,
    quorum: usize,
}

mod branches;
mod inputs;
mod sources;

#[cfg(test)]
mod tests;
