use miden_node_proto::generated as proto;
use miden_node_utils::ErrorReport;
use miden_node_utils::spawn::spawn_blocking_in_current_span;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::transaction::{
    OutputNote,
    ProvenTransaction,
    PublicOutputNote,
    TxAccountUpdate,
};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_tx::TransactionVerifier;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::{Request, Status};
use tracing::{Span, debug};

use super::{COMPONENT, RpcMode, RpcService};
use crate::server::TrustedSubmission;

pub struct SubmitProvenTxInput {
    request: proto::transaction::ProvenTransaction,
    is_authorized_network_tx: bool,
    original_accept_header: Option<MetadataValue<Ascii>>,
}

#[tonic::async_trait]
impl proto::server::rpc_api::SubmitProvenTx for RpcService {
    type Input = SubmitProvenTxInput;
    type Output = proto::blockchain::BlockNumber;

    fn decode(request: proto::transaction::ProvenTransaction) -> tonic::Result<Self::Input> {
        Ok(SubmitProvenTxInput {
            request,
            is_authorized_network_tx: false,
            original_accept_header: None,
        })
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::blockchain::BlockNumber> {
        Ok(output)
    }

    async fn full(
        &self,
        request: Request<proto::transaction::ProvenTransaction>,
    ) -> tonic::Result<proto::blockchain::BlockNumber> {
        let is_authorized_network_tx = self.is_authorized_network_tx(request.metadata());
        let original_accept_header = request.metadata().get(http::header::ACCEPT.as_str()).cloned();

        let mut input = Self::decode(request.into_inner())?;

        input.is_authorized_network_tx = is_authorized_network_tx;
        input.original_accept_header = original_accept_header;

        let output = self.handle(input).await?;
        Self::encode(output)
    }

    async fn handle(&self, input: Self::Input) -> tonic::Result<Self::Output> {
        let SubmitProvenTxInput {
            mut request,
            is_authorized_network_tx,
            original_accept_header,
        } = input;
        debug!(target: COMPONENT, ?request);

        let tx = ProvenTransaction::read_from_bytes(&request.transaction).map_err(|err| {
            Status::invalid_argument(err.as_report_context("invalid transaction"))
        })?;

        let span = Span::current();
        span.set_attribute("transaction.id", tx.id());
        span.set_attribute("account.id", tx.account_id());
        span.set_attribute("transaction.expires_at", tx.expiration_block_num());
        span.set_attribute("transaction.reference_block.number", tx.ref_block_num());
        span.set_attribute("transaction.reference_block.commitment", tx.ref_block_commitment());

        // Verify the reference block is actually part of the chain.
        self.verify_reference_commitment(tx.ref_block_num(), tx.ref_block_commitment())
            .await?;

        // Rebuild a new ProvenTransaction with decorators removed from output notes
        let account_update = TxAccountUpdate::new(
            tx.account_id(),
            tx.account_update().initial_state_commitment(),
            tx.account_update().final_state_commitment(),
            tx.account_update().account_delta_commitment(),
            tx.account_update().details().clone(),
        )
        .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let stripped_outputs = strip_output_note_decorators(tx.output_notes().iter());
        let rebuilt_tx = ProvenTransaction::new(
            account_update,
            tx.input_notes().iter().cloned(),
            stripped_outputs,
            tx.ref_block_num(),
            tx.ref_block_commitment(),
            tx.fee(),
            tx.expiration_block_num(),
            tx.proof().clone(),
        )
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
        request.transaction = rebuilt_tx.to_bytes();

        // Block post-deployment network-account transactions from user RPC. First-deployment txs
        // are exempt because the protocol-level allowlist only kicks in once the account exists,
        // and network accounts must be public, so private-account txs are filtered out up front.
        //
        // Skip this check if the client is authorized to send network transactions (ntx-builder).
        if !is_authorized_network_tx {
            let candidate_id = (!tx.account_update().initial_state_commitment().is_empty()
                && tx.account_id().is_public())
            .then(|| tx.account_id());
            self.reject_if_any_network_accounts(candidate_id).await?;
        }

        let tx_id = tx.id();
        spawn_blocking_in_current_span(move || {
            TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL).verify(&tx).map_err(|err| {
                Status::invalid_argument(format!(
                    "Invalid proof for transaction {}: {}",
                    tx_id,
                    err.as_report()
                ))
            })
        })
        .await
        .map_err(|err| {
            Status::internal(format!("transaction proof verification task failed: {err}"))
        })??;

        match &self.mode {
            RpcMode::Sequencer { block_producer, validator } => {
                Self::submit_to_validator(validator, &request).await?;
                block_producer
                    .submit_proven_tx(rebuilt_tx)
                    .await
                    .map(Into::into)
                    .map_err(Into::into)
            },
            RpcMode::FullNode { source_rpc, trusted, .. } => {
                if let Some(trusted) = trusted {
                    // Trusted full node: validate and authenticate locally, then submit the
                    // authenticated transaction to the sequencer's trusted API.
                    self.submit_authenticated_to_sequencer(trusted, request, &rebuilt_tx).await
                } else {
                    // Untrusted full node: forward the request to the source verbatim.
                    let mut forwarded_request = Request::new(request);
                    if let Some(accept) = original_accept_header {
                        forwarded_request
                            .metadata_mut()
                            .insert(http::header::ACCEPT.as_str(), accept);
                    }
                    source_rpc
                        .as_ref()
                        .clone()
                        .submit_proven_tx(forwarded_request)
                        .await
                        .map(tonic::Response::into_inner)
                }
            },
        }
    }
}

impl RpcService {
    /// Trusted full-node submission path for a single transaction.
    ///
    /// Re-executes the transaction via the validator, authenticates it against the local
    /// (replica) store, then submits the authenticated transaction to the sequencer's
    /// trusted API.
    async fn submit_authenticated_to_sequencer(
        &self,
        trusted: &TrustedSubmission,
        request: proto::transaction::ProvenTransaction,
        rebuilt_tx: &ProvenTransaction,
    ) -> tonic::Result<proto::blockchain::BlockNumber> {
        Self::submit_to_validator(&trusted.validator, &request).await?;

        let auth_inputs = miden_node_block_producer::store::get_tx_inputs(&self.store, rebuilt_tx)
            .await
            .map_err(|err| {
                Status::internal(err.as_report_context("failed to authenticate transaction"))
            })?;

        let authenticated_tx = proto::trusted::AuthenticatedTransaction {
            transaction: request.transaction,
            auth_inputs: Some(auth_inputs.into()),
        };
        trusted
            .sequencer
            .clone()
            .submit_authenticated_tx(authenticated_tx)
            .await
            .map(tonic::Response::into_inner)
    }
}

// HELPERS
// ================================================================================================

/// Strips decorators from public output notes' scripts.
///
/// This removes MAST decorators from note scripts before forwarding to the block producer,
/// as decorators are not needed for transaction processing.
///
/// Note: `PublicOutputNote::new()` already calls `note.minify_script()` internally, so
/// reconstructing the public note through it handles decorator stripping automatically.
fn strip_output_note_decorators<'a>(
    notes: impl Iterator<Item = &'a OutputNote> + 'a,
) -> impl Iterator<Item = OutputNote> + 'a {
    notes.map(|note| match note {
        OutputNote::Public(public_note) => {
            // Reconstruct via PublicOutputNote::new which calls minify_script() internally.
            let rebuilt = PublicOutputNote::new(public_note.as_note().clone())
                .expect("rebuilding an already-valid public output note should not fail");
            OutputNote::Public(rebuilt)
        },
        OutputNote::Private(header) => OutputNote::Private(header.clone()),
    })
}
