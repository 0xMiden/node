use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::transaction::ProvenTransaction;

use crate::errors::ConversionError;
use crate::generated as proto;

#[derive(Debug)]
pub struct ProvenTransactionSubmission {
    pub transaction: ProvenTransaction,
    pub sealed_transaction_inputs: proto::submission::SealedTransactionInputs,
}

impl TryFrom<proto::submission::ProvenTransactionSubmission> for ProvenTransactionSubmission {
    type Error = ConversionError;

    fn try_from(
        value: proto::submission::ProvenTransactionSubmission,
    ) -> Result<Self, Self::Error> {
        let transaction = value
            .transaction
            .ok_or_else(|| {
                ConversionError::missing_field::<proto::submission::ProvenTransactionSubmission>(
                    "transaction",
                )
            })?
            .try_into()
            .map_err(ConversionError::from)?;
        let sealed_transaction_inputs = value.sealed_transaction_inputs.ok_or_else(|| {
            ConversionError::missing_field::<proto::submission::ProvenTransactionSubmission>(
                "sealed_transaction_inputs",
            )
        })?;

        Ok(Self { transaction, sealed_transaction_inputs })
    }
}

impl From<&ProvenTransactionSubmission> for proto::submission::ProvenTransactionSubmission {
    fn from(value: &ProvenTransactionSubmission) -> Self {
        Self {
            transaction: Some((&value.transaction).into()),
            sealed_transaction_inputs: Some(value.sealed_transaction_inputs.clone()),
        }
    }
}

#[derive(Debug)]
pub struct TransactionBatchSubmission {
    pub batch: ProvenBatch,
    pub proposed_batch: ProposedBatch,
    pub sealed_transaction_inputs: Vec<proto::submission::SealedTransactionInputs>,
}

impl TryFrom<proto::submission::TransactionBatch> for TransactionBatchSubmission {
    type Error = ConversionError;

    fn try_from(value: proto::submission::TransactionBatch) -> Result<Self, Self::Error> {
        let proposed_message = value.proposed_batch.ok_or_else(|| {
            ConversionError::missing_field::<proto::submission::TransactionBatch>("proposed_batch")
        })?;
        let batch_message = value.batch.ok_or_else(|| {
            ConversionError::missing_field::<proto::submission::TransactionBatch>("batch")
        })?;

        let proposed_reference_header: BlockHeader = proposed_message
            .reference_block_header
            .clone()
            .ok_or_else(|| {
                ConversionError::missing_field::<proto::transaction::ProposedBatch>(
                    "reference_block_header",
                )
            })?
            .try_into()
            .map_err(ConversionError::from)?;
        let batch_reference_num: BlockNumber = batch_message
            .reference_block_num
            .ok_or_else(|| {
                ConversionError::missing_field::<proto::transaction::ProvenBatch>(
                    "reference_block_num",
                )
            })?
            .into();
        if batch_reference_num != proposed_reference_header.block_num() {
            return Err(ConversionError::message(
                "batch reference block number does not match proposal",
            ));
        }

        let proposed_batch = miden_objects::conversion::decode_proposed_batch(
            proposed_message,
            MIN_PROOF_SECURITY_LEVEL,
        )
        .map_err(ConversionError::from)?;

        let batch = miden_objects::conversion::decode_proven_batch(batch_message, &proposed_batch)
            .map_err(ConversionError::from)?;

        if value.sealed_transaction_inputs.len() != proposed_batch.transactions().len() {
            return Err(ConversionError::message(format!(
                "sealed transaction input count {} does not match proposal transaction count {}",
                value.sealed_transaction_inputs.len(),
                proposed_batch.transactions().len()
            )));
        }

        Ok(Self {
            batch,
            proposed_batch,
            sealed_transaction_inputs: value.sealed_transaction_inputs,
        })
    }
}

impl From<&TransactionBatchSubmission> for proto::submission::TransactionBatch {
    fn from(value: &TransactionBatchSubmission) -> Self {
        Self {
            batch: Some((&value.batch).into()),
            proposed_batch: Some((&value.proposed_batch).into()),
            sealed_transaction_inputs: value.sealed_transaction_inputs.clone(),
        }
    }
}
