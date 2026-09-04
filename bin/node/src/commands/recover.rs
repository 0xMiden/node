use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_node_proto::clients::{Builder, ValidatorClient};
use miden_node_proto::generated::validator::{BlockSubscriptionRequest, BlockSubscriptionResponse};
use miden_node_store::{BlockWriter, State, WriterTask};
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
use miden_protocol::utils::serde::Deserializable;
use tokio::sync::mpsc;
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

    #[command(flatten)]
    store: StoreOptions,
}

impl RecoverCommand {
    pub async fn handle(self) -> anyhow::Result<()> {
        let (state, mut block_writer, writer_task) = self.load_state().await?;
        let validators = self
            .validator_urls
            .iter()
            .map(|url| Ok((url.clone(), Self::validator_client(url)?)))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let result = recover_from_validators(&state, &mut block_writer, validators).await;
        // Wait for the writer to drain and release the backing storage before the process exits.
        block_writer.stop(writer_task).await;
        result
    }

    async fn load_state(&self) -> anyhow::Result<(Arc<State>, BlockWriter, WriterTask)> {
        // Recovery is not wired into the node's shutdown token; the writer exits once the
        // `BlockWriter` (holding the only write handle) is dropped after recovery completes.
        let loaded = State::load_with_database_options(
            &self.data_directory,
            self.store.storage.clone().into(),
            self.store.sqlite.database_options(),
        )
        .await
        .context("failed to load state")?;

        let (state, block_writer, _proof_writer, writer_task) =
            loaded.start(CancellationToken::new());
        Ok((state, block_writer, writer_task))
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
) -> anyhow::Result<()> {
    // Capture the smallest of the validators' chain tips as the recovery target: it is the highest
    // block for which every validator can supply its signature. The validators' block streams
    // follow live blocks indefinitely, so without a fixed target we could never tell when to stop.
    // The sequencer must be shut down during recovery, so these tips do not advance.
    let mut recovery_tip: Option<BlockNumber> = None;
    for (url, validator) in &mut validators {
        let tip = BlockNumber::from(
            validator
                .status(())
                .await
                .with_context(|| format!("failed to query status of validator {url}"))?
                .into_inner()
                .chain_tip,
        );
        recovery_tip = Some(recovery_tip.map_or(tip, |current| current.min(tip)));
    }
    let recovery_tip = recovery_tip.context("at least one validator URL is required")?;

    let local_tip = state.committed_tip();
    if local_tip >= recovery_tip {
        info!(
            target: LOG_TARGET,
            "Local chain is already at the validators' chain tip; nothing to recover",
            block.number = local_tip,
            sync.upstream_block = recovery_tip
        );
        return Ok(());
    }

    // The parent of the first recovered block is the local chain tip; each parent's header commits
    // to the validator keys whose signatures the child block must carry.
    let (parent, _) = state
        .view()
        .get_block_header(Some(local_tip), false)
        .await
        .context("failed to load the local chain tip header")?;
    let parent = parent.context("local chain tip header not found")?;

    let block_from = local_tip.child().as_u32();
    let block_count = u64::from(recovery_tip.as_u32() - block_from) + 1;
    info!(
        target: LOG_TARGET,
        "Recovering blocks from validators",
        block.from = block_from,
        sync.upstream_block = recovery_tip,
        validators.count = validators.len()
    );

    // Run recovery as a three-stage pipeline so that receiving blocks from the validators,
    // signature coalescing and verification, and local block application all overlap: one reader
    // task per validator stream, a coalescer task zipping the readers, and this task applying the
    // coalesced blocks in order.
    let mut block_streams = Vec::with_capacity(validators.len());
    for (url, mut validator) in validators {
        let stream = validator
            .block_subscription(BlockSubscriptionRequest { block_from })
            .await
            .with_context(|| format!("failed to open block subscription on validator {url}"))?
            .into_inner();
        let (block_tx, block_rx) = mpsc::channel(BLOCK_CHANNEL_CAPACITY);
        tokio::spawn(read_blocks(url.clone(), stream, block_count, block_tx));
        block_streams.push((url, block_rx));
    }

    let (coalesced_tx, mut coalesced_rx) = mpsc::channel(BLOCK_CHANNEL_CAPACITY);
    let coalescer =
        tokio::spawn(coalesce_blocks(block_streams, parent, recovery_tip, coalesced_tx));

    while let Some(block) = coalesced_rx.recv().await {
        let block_num = block.header().block_num();
        block_writer
            .apply_block(block)
            .await
            .context("failed to apply recovered block")?;
        info!(target: LOG_TARGET, "Applied recovered block", block.number = block_num);
    }

    // The channel closes either because every block up to the recovery target was coalesced or
    // because the coalescer failed.
    coalescer.await.context("coalescer task panicked")??;

    info!(target: LOG_TARGET, "Block recovery complete", tip.number = recovery_tip);
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
    blocks: mpsc::Sender<anyhow::Result<SignedBlock>>,
) {
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
                SignedBlock::read_from_bytes(&event.block)
                    .with_context(|| format!("failed to deserialize block from validator {url}"))
            });

        let is_err = block.is_err();
        if blocks.send(block).await.is_err() || is_err {
            return;
        }
    }
}

/// Coalesces the per-validator block streams into fully signed, verified blocks and forwards them
/// in block-number order for application.
async fn coalesce_blocks(
    mut block_streams: Vec<(Url, mpsc::Receiver<anyhow::Result<SignedBlock>>)>,
    mut parent: BlockHeader,
    recovery_tip: BlockNumber,
    coalesced: mpsc::Sender<SignedBlock>,
) -> anyhow::Result<()> {
    for block_num in parent.block_num().child().as_u32()..=recovery_tip.as_u32() {
        let block = next_coalesced_block(&mut block_streams, &parent)
            .await
            .with_context(|| format!("failed to reconstruct block {block_num}"))?;
        parent = block.header().clone();

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
    block_streams: &mut [(Url, mpsc::Receiver<anyhow::Result<SignedBlock>>)],
    parent: &BlockHeader,
) -> anyhow::Result<SignedBlock> {
    let expected_block_num = parent.block_num().child();

    let mut signatures = Vec::with_capacity(block_streams.len());
    let mut first_parts: Option<(BlockHeader, BlockBody)> = None;
    for (url, blocks) in block_streams.iter_mut() {
        let block = blocks
            .recv()
            .await
            .with_context(|| format!("block channel of validator {url} closed unexpectedly"))??;

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
            None => first_parts = Some((header, body)),
            Some((first_header, _)) => anyhow::ensure!(
                header.commitment() == first_header.commitment(),
                "validator {url} served a block with commitment {} which diverges from commitment {} served by the first validator",
                header.commitment(),
                first_header.commitment(),
            ),
        }
        signatures.push(signature);
    }
    let (header, body) = first_parts.context("at least one validator stream is required")?;

    let signatures =
        coalesce_signatures(signatures, header.commitment(), parent.validator_config())?;
    let block = SignedBlock::new_unchecked(header, body, signatures);

    // Fully validate the reconstructed block before it is persisted, including verifying the
    // signature set against the parent's validator keys; `BlockWriter::apply_block` does not verify
    // signatures.
    block.validate(Some(parent)).context("coalesced block failed validation")?;

    Ok(block)
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

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::block::ValidatorConfig;
    use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;

    use super::coalesce_signatures;

    fn signers(count: usize) -> Vec<SigningKey> {
        (0..count).map(|_| SigningKey::new()).collect()
    }

    fn validator_keys(signers: &[SigningKey]) -> ValidatorConfig {
        ValidatorConfig::new(
            signers.iter().map(SigningKey::public_key).collect(),
            u16::try_from(signers.len()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn signatures_are_ordered_against_the_validator_set() {
        let commitment = Word::from([1u32, 2, 3, 4]);
        let signers = signers(3);
        let keys = validator_keys(&signers);

        // Collect the signatures in reverse order to prove they get reordered.
        let shuffled = signers.iter().rev().map(|signer| signer.sign(commitment)).collect();

        let coalesced = coalesce_signatures(shuffled, commitment, &keys).unwrap();
        coalesced.verify_against(commitment, &keys).unwrap();
    }

    #[test]
    fn signature_count_mismatch_is_rejected() {
        let commitment = Word::from([1u32, 2, 3, 4]);
        let signers = signers(3);
        let keys = validator_keys(&signers);

        let missing_one = signers.iter().take(2).map(|signer| signer.sign(commitment)).collect();

        let err = coalesce_signatures(missing_one, commitment, &keys).unwrap_err();
        assert!(err.to_string().contains("collected 2 signatures"), "{err}");
    }

    #[test]
    fn duplicate_validator_signature_is_rejected() {
        let commitment = Word::from([1u32, 2, 3, 4]);
        let signers = signers(3);
        let keys = validator_keys(&signers);

        // Two streams served by the same validator: its signature appears twice and the third
        // validator's signature is missing.
        let duplicated = vec![
            signers[0].sign(commitment),
            signers[0].sign(commitment),
            signers[1].sign(commitment),
        ];

        let err = coalesce_signatures(duplicated, commitment, &keys).unwrap_err();
        assert!(err.to_string().contains("no unmatched signature verifies"), "{err}");
    }

    #[test]
    fn foreign_signature_is_rejected() {
        let commitment = Word::from([1u32, 2, 3, 4]);
        let signers = signers(3);
        let keys = validator_keys(&signers);

        // One signature comes from a key outside the validator set.
        let with_foreign = vec![
            signers[0].sign(commitment),
            signers[1].sign(commitment),
            SigningKey::new().sign(commitment),
        ];

        let err = coalesce_signatures(with_foreign, commitment, &keys).unwrap_err();
        assert!(err.to_string().contains("no unmatched signature verifies"), "{err}");
    }
}
