use std::collections::BTreeMap;

use miden_protobuf::{BuildUnchecked, ConversionResultExt, Verify};
use miden_protocol::account::AccountId;
use miden_protocol::batch::{OrderedBatches, ProvenBatch};
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::nullifier_tree::NullifierWitness;
use miden_protocol::block::{BlockHeader, BlockInputs, ProposedBlock};
use miden_protocol::note::{NoteId, NoteInclusionProof, Nullifier};
use miden_protocol::transaction::PartialBlockchain;
use miden_protocol::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

use crate::errors::ConversionError;
use crate::generated as proto;

/// The domain inputs needed by the block prover.
#[derive(Debug)]
pub struct BlockProofRequest {
    pub tx_batches: OrderedBatches,
    pub block_header: BlockHeader,
    pub block_inputs: BlockInputs,
}

impl From<&BlockProofRequest> for proto::block_proving::BlockProofRequest {
    fn from(value: &BlockProofRequest) -> Self {
        Self {
            batches: value.tx_batches.as_slice().iter().map(Into::into).collect(),
            block_inputs: Some((&value.block_inputs).into()),
            timestamp: value.block_header.timestamp(),
            next_validator_config: Some(value.block_header.validator_config().into()),
            next_protocol_config: value.block_header.next_protocol_config().map(Into::into),
        }
    }
}

impl From<BlockProofRequest> for proto::block_proving::BlockProofRequest {
    fn from(value: BlockProofRequest) -> Self {
        Self::from(&value)
    }
}

impl BuildUnchecked for proto::block_proving::DecodedBlockProofRequest {
    type Output = BlockProofRequest;
    type Error = ConversionError;

    /// Reconstruct the proposed block without verifying batch proofs or parent chain state. Batch
    /// construction also skips input-note authentication, aggregation, and transaction order. The
    /// caller must complete these checks before accepting the block.
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        // SAFETY: This unchecked constructor leaves parent authentication to its caller.
        // ProposedBlock checks the supplied chain and witnesses against that parent below.
        let block_inputs = self.block_inputs.build_unchecked().context("block_inputs")?;
        let batches = self
            .batches
            .into_iter()
            .enumerate()
            .map(|(index, batch)| {
                // SAFETY: This unchecked constructor leaves batch validation to its caller.
                // ProposedBlock checks consistency across batches, not within each batch.
                batch.build_unchecked().with_context(|| format!("batches[{index}]"))
            })
            .collect::<Result<Vec<ProvenBatch>, _>>()?;
        let next_validator_config =
            self.next_validator_config.verify().context("next_validator_config")?;
        let next_protocol_config = self
            .next_protocol_config
            .map(Verify::verify)
            .transpose()
            .context("next_protocol_config")?;

        let proposed_block =
            ProposedBlock::new_at(block_inputs.clone(), batches.clone(), self.timestamp)
                .map_err(ConversionError::new)?
                .with_next_validator_config(next_validator_config)
                .with_next_protocol_config(next_protocol_config);
        let (block_header, _) =
            proposed_block.into_header_and_body().map_err(ConversionError::new)?;

        Ok(BlockProofRequest {
            tx_batches: OrderedBatches::new(batches),
            block_header,
            block_inputs,
        })
    }
}

impl From<&BlockInputs> for proto::block_proving::BlockInputs {
    fn from(value: &BlockInputs) -> Self {
        Self {
            prev_block_header: Some(value.prev_block_header().into()),
            partial_blockchain: Some(value.partial_blockchain().into()),
            account_witnesses: value
                .account_witnesses()
                .iter()
                .map(|(account_id, witness)| proto::block_proving::AccountWitnessRecord {
                    account_id: Some((*account_id).into()),
                    witness: Some(witness.into()),
                })
                .collect(),
            nullifier_witnesses: value
                .nullifier_witnesses()
                .iter()
                .map(|(nullifier, witness)| proto::block_proving::NullifierWitness {
                    nullifier: Some(nullifier.as_word().into()),
                    opening: Some(witness.proof().clone().into()),
                })
                .collect(),
            unauthenticated_note_proofs: value
                .unauthenticated_note_proofs()
                .iter()
                .map(Into::into)
                .collect(),
        }
    }
}

impl BuildUnchecked for proto::block_proving::DecodedBlockInputs {
    type Output = BlockInputs;
    type Error = ConversionError;

    /// Build block inputs without checking header linkage, signatures, or protocol transitions.
    /// This includes headers in the partial blockchain. The caller must check the headers, chain
    /// root, and witness roots against trusted chain state.
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        // SAFETY: The caller must authenticate this parent against trusted chain state.
        let prev_block_header: BlockHeader =
            self.prev_block_header.build_unchecked().context("prev_block_header")?;
        // SAFETY: Construction checks MMR membership. The caller must authenticate the MMR root.
        let partial_blockchain: PartialBlockchain =
            self.partial_blockchain.build_unchecked().context("partial_blockchain")?;

        let mut account_witnesses = BTreeMap::<AccountId, AccountWitness>::new();
        for (index, record) in self.account_witnesses.into_iter().enumerate() {
            let account_id = record
                .account_id
                .verify()
                .with_context(|| format!("account_witnesses[{index}].account_id"))?;
            let witness = record
                .witness
                .verify()
                .with_context(|| format!("account_witnesses[{index}].witness"))?;
            if account_witnesses.insert(account_id, witness).is_some() {
                return Err(ConversionError::message(format!(
                    "account_witnesses[{index}]: duplicate requested account ID {account_id}"
                )));
            }
        }

        let mut nullifier_witnesses = BTreeMap::<Nullifier, NullifierWitness>::new();
        for (index, record) in self.nullifier_witnesses.into_iter().enumerate() {
            let nullifier = Nullifier::from_raw(record.nullifier);
            let proof = record
                .opening
                .verify()
                .with_context(|| format!("nullifier_witnesses[{index}].opening"))?;
            if nullifier_witnesses.insert(nullifier, NullifierWitness::new(proof)).is_some() {
                return Err(ConversionError::message(format!(
                    "nullifier_witnesses[{index}]: duplicate nullifier {nullifier}"
                )));
            }
        }

        let mut unauthenticated_note_proofs = BTreeMap::<NoteId, NoteInclusionProof>::new();
        for (index, proof) in self.unauthenticated_note_proofs.into_iter().enumerate() {
            let (note_id, proof) = proof
                .verify()
                .with_context(|| format!("unauthenticated_note_proofs[{index}]"))?;
            if unauthenticated_note_proofs.insert(note_id, proof).is_some() {
                return Err(ConversionError::message(format!(
                    "unauthenticated_note_proofs[{index}]: duplicate note ID {note_id}"
                )));
            }
        }

        Ok(BlockInputs::new(
            prev_block_header,
            partial_blockchain,
            account_witnesses,
            nullifier_witnesses,
            unauthenticated_note_proofs,
        ))
    }
}

impl Serializable for BlockProofRequest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { tx_batches, block_header, block_inputs } = self;
        tx_batches.write_into(target);
        block_header.write_into(target);
        block_inputs.write_into(target);
    }
}

impl Deserializable for BlockProofRequest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            tx_batches: OrderedBatches::read_from(source)?,
            block_header: BlockHeader::read_from(source)?,
            block_inputs: BlockInputs::read_from(source)?,
        })
    }
}
