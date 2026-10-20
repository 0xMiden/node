use miden_node_proto::generated as grpc;
use miden_node_utils::ErrorReport;
use miden_node_utils::spawn::spawn_blocking_in_current_span;
use miden_node_utils::tracing::{miden_instrument, miden_span_record};

use crate::COMPONENT;
use crate::server::proof_kind::ProofKind;
use crate::server::service::ProverService;

#[tonic::async_trait]
impl grpc::server::remote_prover_api::Prove for ProverService {
    type Input = (ProofKind, grpc::remote_prover::ProofRequest);
    type Output = grpc::remote_prover::Proof;

    #[miden_instrument(
        target = COMPONENT,
        name = "remote_prover.prove",
        err,
    )]
    async fn handle(
        &self,
        (proof_kind, request): Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        miden_span_record!(
            request.kind = %proof_kind,
        );

        // Reject unsupported proof types early so they don't clog the queue.
        if !self.is_supported(proof_kind) {
            return Err(tonic::Status::invalid_argument("unsupported proof type"));
        }

        // This semaphore acts like a queue, but with a fixed capacity.
        //
        // We need to hold this until our request is processed to ensure that the queue capacity is
        // not exceeded.
        let permit = self.acquire_permit()?;

        // This mutex is fair and uses FIFO ordering.
        let prover = self.acquire_prover().await;
        let task_panic_context = prover.task_panic_context();

        spawn_blocking_in_current_span(move || {
            let _permit = permit;
            prover.prove(request)
        })
        .await
        .map_err(|e| tonic::Status::internal(e.as_report_context(task_panic_context)))?
    }

    fn decode(request: grpc::remote_prover::ProofRequest) -> tonic::Result<Self::Input> {
        // Check that the proof type is supported. Protobuf enums return a default value if the enum
        // is set to an unknown value. This round trip checks that the value is valid.
        if request.proof_type() as i32 != request.proof_type {
            return Err(tonic::Status::invalid_argument("unknown proof_type value"));
        }

        Ok((ProofKind::from(request.proof_type()), request))
    }

    fn encode(output: Self::Output) -> tonic::Result<grpc::remote_prover::Proof> {
        Ok(output)
    }
}
