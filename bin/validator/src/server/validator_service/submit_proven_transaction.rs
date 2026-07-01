use std::sync::atomic::Ordering;

use miden_node_proto::generated as grpc;
use miden_node_utils::ErrorReport;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::transaction::{ProvenTransaction, TransactionInputs};
use miden_tx::utils::serde::Deserializable;
use tonic::Status;

use super::ValidatorService;
use crate::db::{insert_transaction, transaction_exists};
use crate::tx_validation::validate_transaction;

#[tonic::async_trait]
impl grpc::server::validator_api::SubmitProvenTransaction for ValidatorService {
    type Input = Input;
    type Output = ();

    async fn handle(&self, input: Self::Input) -> tonic::Result<Self::Output> {
        // Reject requests while a backup subscription is streaming.
        let _guard = self
            .serve_lock
            .try_read()
            .map_err(|_| Status::resource_exhausted("validator is busy streaming a backup"))?;

        let tx_id = input.tx.id();
        tracing::Span::current().set_attribute("transaction.id", tx_id);

        // Short-circuit transactions that have already been validated.
        let already_validated = self
            .db
            .read("transaction_exists", move |tx| transaction_exists(tx, tx_id))
            .await
            .map_err(|err| {
                Status::internal(err.as_report_context("Failed to query transaction"))
            })?;
        if already_validated {
            return Ok(());
        }

        // Validate the transaction.
        let tx_info = validate_transaction(input.tx, input.inputs).await.map_err(|err| {
            Status::invalid_argument(err.as_report_context("Invalid transaction"))
        })?;

        // Store the validated transaction.
        let count = self
            .db
            .write("insert_transaction", move |tx| insert_transaction(tx, &tx_info))
            .await
            .map_err(|err| {
                Status::internal(err.as_report_context("Failed to insert transaction"))
            })?;

        self.validated_transactions_count.fetch_add(count as u64, Ordering::Relaxed);
        Ok(())
    }

    fn decode(request: grpc::transaction::ProvenTransaction) -> tonic::Result<Self::Input> {
        let tx = ProvenTransaction::read_from_bytes(&request.transaction).map_err(|err| {
            Status::invalid_argument(err.as_report_context("Invalid proven transaction"))
        })?;
        let inputs = request
            .transaction_inputs
            .ok_or(Status::invalid_argument("Missing transaction inputs"))?;
        let inputs = TransactionInputs::read_from_bytes(&inputs).map_err(|err| {
            Status::invalid_argument(err.as_report_context("Invalid transaction inputs"))
        })?;

        Ok(Self::Input { tx, inputs })
    }

    fn encode(output: Self::Output) -> tonic::Result<()> {
        Ok(output)
    }
}

pub struct Input {
    tx: ProvenTransaction,
    inputs: TransactionInputs,
}
