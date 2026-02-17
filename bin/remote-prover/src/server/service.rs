use std::num::NonZeroUsize;

use miden_node_utils::tracing::OpenTelemetrySpanExt;
use tokio::sync::{Mutex, MutexGuard, SemaphorePermit};
use tracing::instrument;

use crate::server::proof_kind::ProofKind;
use crate::server::prover::Prover;
use crate::{COMPONENT, generated as proto};

pub struct ProverService {
    permits: tokio::sync::Semaphore,
    prover: tokio::sync::Mutex<Prover>,
    kind: ProofKind,
}

impl ProverService {
    pub fn with_capacity(kind: ProofKind, capacity: NonZeroUsize) -> Self {
        let permits = tokio::sync::Semaphore::new(capacity.get());
        let prover = Mutex::new(Prover::new(kind));
        Self { permits, prover, kind }
    }

    fn is_supported(&self, kind: ProofKind) -> bool {
        self.kind == kind
    }

    #[instrument(target=COMPONENT, skip_all, err)]
    fn acquire_permit(&self) -> Result<SemaphorePermit<'_>, tonic::Status> {
        self.permits
            .try_acquire()
            .map_err(|_| tonic::Status::resource_exhausted("proof queue is full"))
    }

    #[instrument(target=COMPONENT, skip_all)]
    async fn acquire_prover_lock(&self) -> MutexGuard<'_, Prover> {
        self.prover.lock().await
    }
}

#[async_trait::async_trait]
impl proto::api_server::Api for ProverService {
    async fn prove(
        &self,
        request: tonic::Request<proto::ProofRequest>,
    ) -> Result<tonic::Response<proto::Proof>, tonic::Status> {
        // Record X-Request-ID header for trace correlation
        let request_id = request
            .metadata()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown");
        tracing::Span::current().set_attribute("request.id", request_id);

        // Check that the proof type is supported.
        let request = request.into_inner();
        // Protobuf enums return a default value if the enum is set to an unknown value.
        // This round trip checks that the value is valid.
        if request.proof_type() as i32 != request.proof_type {
            return Err(tonic::Status::invalid_argument("unknown proof_type value"));
        }
        let proof_kind = ProofKind::from(request.proof_type());
        tracing::Span::current().set_attribute("request.kind", proof_kind);

        // Reject unsupported proof types early so they don't clog the queue.
        if !self.is_supported(proof_kind) {
            return Err(tonic::Status::invalid_argument("unsupported proof type"));
        }

        // This semaphore acts like a queue, but with a fixed capacity.
        //
        // We need to hold this until our request is processed to ensure that the queue capacity is
        // not exceeded.
        let _permit = self.acquire_permit()?;

        // This mutex is fair and uses FIFO ordering.
        let prover = self.acquire_prover_lock().await;

        // Blocking in place is fairly safe since we guarantee that only a single request is
        // processed at a time.
        tokio::task::block_in_place(|| prover.prove(request)).map(tonic::Response::new)
    }
}
