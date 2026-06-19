use anyhow::Context;
use miden_node_block_producer::store::TransactionInputs;
use miden_node_block_producer::{AuthenticatedTransaction, BlockProducerApi};
use miden_node_proto::generated as proto;
use miden_node_proto::generated::pre_authenticated::api_server;
use miden_node_proto::generated::server::pre_authenticated_api;
use miden_node_utils::ErrorReport;
use miden_node_utils::clap::GrpcOptionsInternal;
use miden_node_utils::panic::{CatchPanicLayer, catch_panic_layer_fn};
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use miden_protocol::batch::ProposedBatch;
use miden_protocol::utils::serde::Deserializable;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Status;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::COMPONENT;

/// The pre-authenticated submission server.
///
/// Serves the private `pre_authenticated.Api` gRPC service, which accepts already-authenticated
/// transactions from trusted full nodes and submits them directly to the mempool *without*
/// re-verification.
///
/// This must only ever be exposed on a private, network-isolated listener: callers can inject
/// transactions that the sequencer will not independently verify.
pub struct PreAuthenticated {
    /// The listener the pre-authenticated submission service binds to.
    pub listener: TcpListener,
    /// The in-process block producer API submissions are forwarded to.
    pub block_producer: BlockProducerApi,
    /// gRPC server options for internal services (timeouts).
    pub grpc_options: GrpcOptionsInternal,
}

impl PreAuthenticated {
    /// Serves the pre-authenticated submission API.
    ///
    /// Executes in place (i.e. not spawned) and will run indefinitely until a fatal error is
    /// encountered.
    pub async fn serve(self) -> anyhow::Result<()> {
        info!(target: COMPONENT, endpoint = ?self.listener, "Pre-authenticated submission server initialized");

        let service = PreAuthenticatedService { block_producer: self.block_producer };

        // Note: deliberately no accept-header / rate-limit / auth layers; this is a private,
        // trusted interface and is expected to be network-isolated.
        tonic::transport::Server::builder()
            .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
            .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
            .timeout(self.grpc_options.request_timeout)
            .add_service(api_server::ApiServer::new(service))
            .serve_with_incoming(TcpListenerStream::new(self.listener))
            .await
            .context("failed to serve pre-authenticated submission API")
    }
}

// PRE-AUTHENTICATED SERVICE
// ================================================================================================

struct PreAuthenticatedService {
    block_producer: BlockProducerApi,
}

#[tonic::async_trait]
impl pre_authenticated_api::SubmitAuthenticatedTx for PreAuthenticatedService {
    type Input = AuthenticatedTransaction;
    type Output = proto::blockchain::BlockNumber;

    fn decode(
        request: proto::pre_authenticated::AuthenticatedTransaction,
    ) -> tonic::Result<Self::Input> {
        AuthenticatedTransaction::try_from(request).map_err(|err| {
            Status::invalid_argument(err.as_report_context("invalid authenticated transaction"))
        })
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::blockchain::BlockNumber> {
        Ok(output)
    }

    async fn handle(&self, tx: Self::Input) -> tonic::Result<Self::Output> {
        self.block_producer
            .submit_authenticated_tx(tx)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }
}

#[tonic::async_trait]
impl pre_authenticated_api::SubmitAuthenticatedTxBatch for PreAuthenticatedService {
    type Input = (ProposedBatch, Vec<TransactionInputs>);
    type Output = proto::blockchain::BlockNumber;

    fn decode(
        request: proto::pre_authenticated::AuthenticatedTransactionBatch,
    ) -> tonic::Result<Self::Input> {
        let batch = ProposedBatch::read_from_bytes(&request.proposed_batch).map_err(|err| {
            Status::invalid_argument(err.as_report_context("invalid proposed_batch"))
        })?;
        let inputs = request
            .auth_inputs
            .into_iter()
            .map(TransactionInputs::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                Status::invalid_argument(err.as_report_context("invalid auth_inputs"))
            })?;

        if batch.transactions().len() != inputs.len() {
            return Err(Status::invalid_argument(format!(
                "Number of inputs {} does not match number of transactions {} in batch",
                inputs.len(),
                batch.transactions().len()
            )));
        }

        Ok((batch, inputs))
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::blockchain::BlockNumber> {
        Ok(output)
    }

    async fn handle(&self, (batch, inputs): Self::Input) -> tonic::Result<Self::Output> {
        self.block_producer
            .submit_authenticated_tx_batch(batch, inputs)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }
}
