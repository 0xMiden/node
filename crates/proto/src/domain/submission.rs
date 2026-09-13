use miden_protobuf::{BuildUnchecked, ConversionResultExt, Verify, VerifyWith};
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_protocol::transaction::ProvenTransaction;

use crate::errors::ConversionError;
use crate::generated as proto;

#[derive(Debug)]
pub struct ProvenTransactionSubmission {
    pub transaction: ProvenTransaction,
    pub sealed_transaction_inputs: proto::submission::SealedTransactionInputs,
}

impl BuildUnchecked for proto::submission::DecodedProvenTransactionSubmission {
    type Output = ProvenTransactionSubmission;
    type Error = ConversionError;

    /// Build the submission without checking the proof, input-note authentication, or sealed
    /// inputs. The caller must verify the proof, authenticate the input notes, and unseal the
    /// inputs.
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        // SAFETY: This unchecked constructor leaves proof verification and note authentication to
        // the receiving service. The sealed inputs also require decryption and validation.
        let transaction = self.transaction.build_unchecked().context("transaction")?;
        let sealed_transaction_inputs = self.sealed_transaction_inputs.into();
        Ok(ProvenTransactionSubmission { transaction, sealed_transaction_inputs })
    }
}

impl From<proto::submission::DecodedSealedTransactionInputs>
    for proto::submission::SealedTransactionInputs
{
    fn from(value: proto::submission::DecodedSealedTransactionInputs) -> Self {
        Self {
            key_id: value.key_id,
            ciphertext: value.ciphertext,
        }
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

impl Verify for proto::submission::DecodedTransactionBatch {
    type Verified = TransactionBatchSubmission;
    type Error = ConversionError;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let batch_reference_num = self.batch.reference_block_num.block_num;
        let proposed_reference_num = self.proposed_batch.reference_block_header.block_num.block_num;
        if batch_reference_num != proposed_reference_num {
            return Err(ConversionError::message(
                "batch reference block number does not match proposal",
            ));
        }

        let proposed_batch = self
            .proposed_batch
            .verify_with(MIN_PROOF_SECURITY_LEVEL)
            .context("proposed_batch")?;
        let batch = self.batch.verify_with(&proposed_batch).context("batch")?;

        if self.sealed_transaction_inputs.len() != proposed_batch.transactions().len() {
            return Err(ConversionError::message(format!(
                "sealed transaction input count {} does not match proposal transaction count {}",
                self.sealed_transaction_inputs.len(),
                proposed_batch.transactions().len()
            )));
        }

        Ok(TransactionBatchSubmission {
            batch,
            proposed_batch,
            sealed_transaction_inputs: self
                .sealed_transaction_inputs
                .into_iter()
                .map(Into::into)
                .collect(),
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
