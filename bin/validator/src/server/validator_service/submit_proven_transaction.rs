use std::future::Future;
use std::sync::atomic::Ordering;

use miden_node_proto::generated as grpc;
use miden_node_utils::ErrorReport;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::transaction::{ProvenTransaction, TransactionInputs};
use miden_tx::utils::serde::{Deserializable, Serializable};
use tonic::Status;

use super::ValidatorService;
use crate::db::insert_transaction;
use crate::tx_validation::validate_transaction;

#[tonic::async_trait]
impl grpc::server::validator_api::SubmitProvenTransaction for ValidatorService {
    type Input = Input;
    type Output = ();

    async fn handle(&self, input: Self::Input) -> tonic::Result<Self::Output> {
        tracing::Span::current().set_attribute("transaction.id", input.tx.id());

        // Forward the request to the standby validator, if one is configured, concurrently with
        // local processing so the standby's latency is hidden. The standby is best-effort: failures
        // are logged but never propagated.
        let forward = self.forward_submit_proven_transaction(&input.tx, &input.inputs);

        let local = async move {
            // Validate the transaction.
            let tx_info = validate_transaction(input.tx, input.inputs).await.map_err(|err| {
                Status::invalid_argument(err.as_report_context("Invalid transaction"))
            })?;

            // Store the validated transaction.
            let count = self
                .db
                .transact("insert_transaction", move |conn| insert_transaction(conn, &tx_info))
                .await
                .map_err(|err| {
                    Status::internal(err.as_report_context("Failed to insert transaction"))
                })?;

            self.validated_transactions_count.fetch_add(count as u64, Ordering::Relaxed);
            Ok::<_, Status>(())
        };

        // Both the local processing and the standby forward must succeed. The primary's own
        // validation error takes precedence; only if it succeeds do we surface a standby failure.
        let (result, forward) = tokio::join!(local, forward);
        result?;
        forward
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

impl ValidatorService {
    /// Forwards a `submit_proven_transaction` request to the standby validator, if one is
    /// configured.
    ///
    /// `use<>` keeps the future from borrowing the transaction, so the caller can move it into
    /// local validation while the forward is in flight.
    fn forward_submit_proven_transaction(
        &self,
        tx: &ProvenTransaction,
        inputs: &TransactionInputs,
    ) -> impl Future<Output = tonic::Result<()>> + use<> {
        let forward = self.standby.clone().map(|client| {
            let request = grpc::transaction::ProvenTransaction {
                transaction: tx.to_bytes(),
                transaction_inputs: Some(inputs.to_bytes()),
            };
            (client, request)
        });
        async move {
            let Some((mut client, request)) = forward else {
                return Ok(());
            };
            client.submit_proven_transaction(request).await.map(|_| ()).map_err(|err| {
                Status::internal(format!(
                    "failed to forward submit_proven_transaction to standby validator: {}",
                    err.as_report()
                ))
            })
        }
    }
}

pub struct Input {
    tx: ProvenTransaction,
    inputs: TransactionInputs,
}
