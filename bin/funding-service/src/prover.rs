//! Transaction proving.

use std::time::Duration;

use anyhow::{Context, Result};
use miden_node_proto::clients::{Builder, RemoteProverClient};
use miden_node_proto::generated::remote_prover::ProofRequest;
use miden_node_proto::generated::remote_prover::proof::Proof as ProofVariant;
use miden_node_proto::generated::remote_prover::proof_request::Request as ProofRequestVariant;
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_node_tracing::{ErrorReport, warn};
use miden_protocol::transaction::{ExecutedTransaction, ProvenTransaction};
use miden_tx::LocalTransactionProver;
use url::Url;

use crate::COMPONENT;

// PROVER
// ================================================================================================

/// The prover the service is configured with.
#[derive(Clone)]
pub enum Prover {
    /// Proves in this process.
    Local(LocalProver),
    /// Proves through a remote prover, and falls back to local proving on failure.
    Remote(Box<RemoteProver>),
}

impl Prover {
    /// Builds a local prover.
    pub fn local() -> Self {
        Self::Local(LocalProver)
    }

    /// Builds a prover which uses the remote prover at `url`, with local proving as a fallback.
    pub fn remote(url: Url, timeout: Duration) -> Result<Self> {
        Ok(Self::Remote(Box::new(RemoteProver::new(url, timeout)?)))
    }

    /// Proves one executed transaction.
    pub async fn prove(&self, executed_tx: ExecutedTransaction) -> Result<ProvenTransaction> {
        match self {
            Self::Local(prover) => prover.prove(executed_tx).await,
            Self::Remote(prover) => prover.prove(executed_tx).await,
        }
    }
}

// LOCAL PROVER
// ================================================================================================

/// Proves transactions in this process.
#[derive(Clone, Copy)]
pub struct LocalProver;

impl LocalProver {
    /// Proves one executed transaction in this process.
    pub async fn prove(&self, executed_tx: ExecutedTransaction) -> Result<ProvenTransaction> {
        // Proving is CPU bound and would block the runtime's worker thread.
        spawn_blocking_in_current_span(move || {
            LocalTransactionProver::default()
                .prove(executed_tx)
                .context("failed to prove the transaction locally")
        })
        .await
        .context("the local proving task failed")?
    }
}

// REMOTE PROVER
// ================================================================================================

/// Proves transactions through the remote prover service, with local proving as a fallback.
#[derive(Clone)]
pub struct RemoteProver {
    client: RemoteProverClient,
    fallback: LocalProver,
}

impl RemoteProver {
    /// Creates a prover with a lazy connection to the given gRPC endpoint.
    pub fn new(url: Url, timeout: Duration) -> Result<Self> {
        let client = Builder::new(url)
            .with_tls()
            .context("failed to configure TLS for the remote prover client")?
            .with_timeout(timeout)
            .without_metadata_version()
            .without_metadata_genesis()
            .without_auth_header()
            .with_otel_context_injection()
            .connect_lazy::<RemoteProverClient>();

        Ok(Self { client, fallback: LocalProver })
    }

    /// Proves one transaction on the remote prover.
    async fn prove_remotely(&self, executed_tx: &ExecutedTransaction) -> Result<ProvenTransaction> {
        let request = tonic::Request::new(ProofRequest {
            request: Some(ProofRequestVariant::Transaction(executed_tx.tx_inputs().into())),
        });

        let response = self
            .client
            .clone()
            .prove(request)
            .await
            .context("the remote prover rejected the transaction")?;

        let proof = match response.into_inner().proof {
            Some(ProofVariant::Transaction(proof)) => proof,
            Some(_) => anyhow::bail!("the remote prover answered with a proof of another kind"),
            None => anyhow::bail!("the remote prover response holds no proof"),
        };

        ProvenTransaction::try_from(proof)
            .context("failed to decode the response of the remote transaction prover")
    }

    /// Proves one executed transaction, falling back to local proving.
    pub async fn prove(&self, executed_tx: ExecutedTransaction) -> Result<ProvenTransaction> {
        match self.prove_remotely(&executed_tx).await {
            Ok(proven_tx) => Ok(proven_tx),
            Err(err) => {
                warn!(
                    &err,
                    target: COMPONENT,
                    "Remote proving failed, proving locally instead"
                );
                self.fallback.prove(executed_tx).await.with_context(|| {
                    format!("local proving after a remote prover failure: {}", err.as_report())
                })
            },
        }
    }
}
