use miden_node_proto::generated as grpc;
use miden_node_utils::ErrorReport;
use miden_protocol::transaction::{ProvenTransaction, TransactionInputs};
use miden_tx::utils::Deserializable;

use crate::db::insert_transaction;
use crate::server::ValidatorServer;
use crate::tx_validation::validate_transaction;

#[tonic::async_trait]
impl grpc::server::validator_api::SubmitProvenTransaction for ValidatorServer {
    type Input = Input;
    type Output = ();

    async fn handle(&self, input: Self::Input) -> tonic::Result<Self::Output> {
        let tx_info = validate_transaction(input.tx, input.inputs).await.map_err(|err| {
            tonic::Status::invalid_argument(err.as_report_context("Invalid transaction"))
        })?;

        // Store the validated transaction.
        self.db
            .transact("insert_transaction", move |conn| insert_transaction(conn, &tx_info))
            .await
            .map_err(|err| {
                tonic::Status::internal(err.as_report_context("Failed to insert transaction"))
            })?;

        Ok(())
    }

    fn decode(request: grpc::transaction::ProvenTransaction) -> tonic::Result<Self::Input> {
        let tx = ProvenTransaction::read_from_bytes(&request.transaction).map_err(|err| {
            tonic::Status::invalid_argument(err.as_report_context("invalid transaction"))
        })?;
        let inputs =
            TransactionInputs::read_from_bytes(&request.transaction_inputs()).map_err(|err| {
                tonic::Status::invalid_argument(err.as_report_context("invalid transaction inputs"))
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
