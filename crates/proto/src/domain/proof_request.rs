use std::collections::BTreeMap;

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
            protocol_config: None,
        }
    }
}

impl From<BlockProofRequest> for proto::block_proving::BlockProofRequest {
    fn from(value: BlockProofRequest) -> Self {
        Self::from(&value)
    }
}

impl TryFrom<proto::block_proving::BlockProofRequest> for BlockProofRequest {
    type Error = ConversionError;

    fn try_from(value: proto::block_proving::BlockProofRequest) -> Result<Self, Self::Error> {
        let block_inputs: BlockInputs = value
            .block_inputs
            .ok_or_else(|| {
                ConversionError::missing_field::<proto::block_proving::BlockProofRequest>(
                    "block_inputs",
                )
            })?
            .try_into()?;

        let batches = value
            .batches
            .into_iter()
            .enumerate()
            .map(|(index, batch)| {
                miden_objects::conversion::decode_standalone_proven_batch(batch).map_err(|error| {
                    ConversionError::from(error.context(format!("batches[{index}]")))
                })
            })
            .collect::<Result<Vec<ProvenBatch>, _>>()?;

        let next_validator_config = value
            .next_validator_config
            .ok_or_else(|| {
                ConversionError::missing_field::<proto::block_proving::BlockProofRequest>(
                    "next_validator_config",
                )
            })?
            .try_into()
            .map_err(ConversionError::from)?;
        let next_protocol_config = value
            .next_protocol_config
            .map(TryInto::try_into)
            .transpose()
            .map_err(ConversionError::from)?;

        let proposed_block =
            ProposedBlock::new_at(block_inputs.clone(), batches.clone(), value.timestamp)
                .map_err(ConversionError::new)?
                .with_next_validator_config(next_validator_config)
                .with_next_protocol_config(next_protocol_config);
        let (block_header, _) =
            proposed_block.into_header_and_body().map_err(ConversionError::new)?;

        Ok(Self {
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

impl TryFrom<proto::block_proving::BlockInputs> for BlockInputs {
    type Error = ConversionError;

    fn try_from(value: proto::block_proving::BlockInputs) -> Result<Self, Self::Error> {
        let prev_block_header = required::<proto::block_proving::BlockInputs, _, BlockHeader>(
            value.prev_block_header,
            "prev_block_header",
        )?;
        let partial_blockchain = required::<proto::block_proving::BlockInputs, _, PartialBlockchain>(
            value.partial_blockchain,
            "partial_blockchain",
        )?;

        let mut account_witnesses = BTreeMap::<AccountId, AccountWitness>::new();
        for (index, record) in value.account_witnesses.into_iter().enumerate() {
            let account_id = required::<proto::block_proving::AccountWitnessRecord, _, AccountId>(
                record.account_id,
                "account_id",
            )?;
            let witness = required::<proto::block_proving::AccountWitnessRecord, _, AccountWitness>(
                record.witness,
                "witness",
            )?;
            if account_witnesses.insert(account_id, witness).is_some() {
                return Err(ConversionError::message(format!(
                    "account_witnesses[{index}]: duplicate requested account ID {account_id}"
                )));
            }
        }

        let mut nullifier_witnesses = BTreeMap::<Nullifier, NullifierWitness>::new();
        for (index, record) in value.nullifier_witnesses.into_iter().enumerate() {
            let nullifier_word = required::<
                proto::block_proving::NullifierWitness,
                _,
                miden_protocol::Word,
            >(record.nullifier, "nullifier")?;
            let nullifier = Nullifier::from_raw(nullifier_word);
            let proof = required::<
                proto::block_proving::NullifierWitness,
                _,
                miden_protocol::crypto::merkle::smt::SmtProof,
            >(record.opening, "opening")?;
            if nullifier_witnesses.insert(nullifier, NullifierWitness::new(proof)).is_some() {
                return Err(ConversionError::message(format!(
                    "nullifier_witnesses[{index}]: duplicate nullifier {nullifier}"
                )));
            }
        }

        let mut unauthenticated_note_proofs = BTreeMap::<NoteId, NoteInclusionProof>::new();
        for (index, proof) in value.unauthenticated_note_proofs.into_iter().enumerate() {
            let (note_id, proof) =
                <(NoteId, NoteInclusionProof)>::try_from(&proof).map_err(ConversionError::from)?;
            if unauthenticated_note_proofs.insert(note_id, proof).is_some() {
                return Err(ConversionError::message(format!(
                    "unauthenticated_note_proofs[{index}]: duplicate note ID {note_id}"
                )));
            }
        }

        Ok(Self::new(
            prev_block_header,
            partial_blockchain,
            account_witnesses,
            nullifier_witnesses,
            unauthenticated_note_proofs,
        ))
    }
}

fn required<M, T, U>(value: Option<T>, field: &'static str) -> Result<U, ConversionError>
where
    M: prost::Message,
    T: TryInto<U>,
    T::Error: Into<miden_objects::ConversionError>,
{
    value
        .ok_or_else(|| ConversionError::missing_field::<M>(field))?
        .try_into()
        .map_err(Into::into)
        .map_err(ConversionError::from)
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
