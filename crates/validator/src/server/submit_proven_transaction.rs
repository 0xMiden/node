use miden_node_proto::generated as grpc;
use miden_node_proto::generated::server::validator_api::SubmitProvenTransaction;
use miden_node_proto::server::GrpcDecode;
use miden_node_utils::ErrorReport;
use miden_protocol::transaction::{ProvenTransaction, TransactionInputs};
use miden_tx::utils::Deserializable;

use crate::db::insert_transaction;
use crate::server::ValidatorServer;
use crate::tx_validation::validate_transaction;

#[tonic::async_trait]
impl miden_node_proto::server::GrpcUnary<SubmitProvenTransaction> for ValidatorServer {
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
}

pub struct Input {
    tx: ProvenTransaction,
    inputs: TransactionInputs,
}

impl GrpcDecode<grpc::transaction::ProvenTransaction> for Input {
    type Error = miden_protocol::utils::DeserializationError;

    fn decode(input: grpc::transaction::ProvenTransaction) -> Result<Self, Self::Error> {
        let tx = ProvenTransaction::read_from_bytes(&input.transaction)?;
        let inputs = TransactionInputs::read_from_bytes(&input.transaction_inputs())?;

        Ok(Self { tx, inputs })
    }
}
