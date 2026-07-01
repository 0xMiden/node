use std::num::NonZeroUsize;

use miden_node_utils::tracing::miden_instrument;
use tokio::sync::{Mutex, MutexGuard, SemaphorePermit};

use crate::COMPONENT;
use crate::server::proof_kind::ProofKind;
use crate::server::prover::Prover;

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

    pub(super) fn is_supported(&self, kind: ProofKind) -> bool {
        self.kind == kind
    }

    #[miden_instrument(target=COMPONENT, skip_all, err)]
    pub(super) fn acquire_permit(&self) -> Result<SemaphorePermit<'_>, tonic::Status> {
        self.permits
            .try_acquire()
            .map_err(|_| tonic::Status::resource_exhausted("proof queue is full"))
    }

    #[miden_instrument(target=COMPONENT, skip_all)]
    pub(super) async fn acquire_prover(&self) -> MutexGuard<'_, Prover> {
        self.prover.lock().await
    }
}
