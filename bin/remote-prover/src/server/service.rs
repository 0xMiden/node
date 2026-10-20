use std::num::NonZeroUsize;
use std::sync::Arc;

use miden_node_utils::tracing::miden_instrument;
use tokio::sync::{Mutex, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore};

use crate::COMPONENT;
use crate::server::proof_kind::ProofKind;
use crate::server::prover::Prover;

pub struct ProverService {
    permits: Arc<Semaphore>,
    prover: Arc<tokio::sync::Mutex<Prover>>,
    kind: ProofKind,
}

impl ProverService {
    pub fn with_capacity(kind: ProofKind, capacity: NonZeroUsize) -> Self {
        let permits = Arc::new(Semaphore::new(capacity.get()));
        let prover = Arc::new(Mutex::new(Prover::new(kind)));
        Self { permits, prover, kind }
    }

    pub(super) fn is_supported(&self, kind: ProofKind) -> bool {
        self.kind == kind
    }

    #[miden_instrument(
        target=COMPONENT,
        err,
    )]
    pub(super) fn acquire_permit(&self) -> Result<OwnedSemaphorePermit, tonic::Status> {
        Arc::clone(&self.permits)
            .try_acquire_owned()
            .map_err(|_| tonic::Status::resource_exhausted("proof queue is full"))
    }

    #[miden_instrument(
        target=COMPONENT,
    )]
    pub(super) async fn acquire_prover(&self) -> OwnedMutexGuard<Prover> {
        Arc::clone(&self.prover).lock_owned().await
    }
}
