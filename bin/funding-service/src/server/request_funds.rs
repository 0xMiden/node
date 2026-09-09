use axum::Json;
use axum::extract::State;
use miden_protocol::account::AccountId;
use miden_protocol::utils::serde::Serializable;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

use crate::COMPONENT;
use crate::error::RequestFundsError;
use crate::server::FundingState;
use crate::worker::{FundedNote, FundingRequest};

// REQUEST AND RESPONSE
// ================================================================================================

/// The body of a funding request.
#[derive(Debug, Deserialize, Serialize)]
pub(super) struct RequestFundsRequest {
    /// The account which the note targets, in hexadecimal.
    account_id: String,

    /// The amount of the native asset, in base units.
    amount: u64,
}

/// The body of a successful funding response.
#[derive(Debug, Deserialize, Serialize)]
pub(super) struct RequestFundsResponse {
    /// The serialized note, in hexadecimal.
    note: String,

    /// The serialized proof that the note is in a block, in hexadecimal.
    inclusion_proof: String,

    /// The transaction which created the note, in hexadecimal.
    transaction_id: String,
}

impl From<FundedNote> for RequestFundsResponse {
    fn from(funded: FundedNote) -> Self {
        let FundedNote { note, inclusion_proof, transaction_id } = funded;

        Self {
            note: hex::encode(note.to_bytes()),
            inclusion_proof: hex::encode(inclusion_proof.to_bytes()),
            transaction_id: hex::encode(transaction_id.to_bytes()),
        }
    }
}

// REQUEST FUNDS HANDLER
// ================================================================================================

/// Creates a private P2ID note which holds `amount` base units of the native asset and targets
/// `account_id`, then waits for the note to commit.
#[miden_node_tracing::miden_instrument(
    target = COMPONENT,
    name = "request_funds",
    fields (
        account.id = request.account_id,
        asset.amount = request.amount,
    ),
    err,
)]
pub(super) async fn request_funds(
    State(state): State<FundingState>,
    Json(request): Json<RequestFundsRequest>,
) -> Result<Json<RequestFundsResponse>, RequestFundsError> {
    let target = AccountId::from_hex(&request.account_id)
        .map_err(|_| RequestFundsError::InvalidAccountId)?;
    validate_amount(request.amount, state.status.max_amount())?;

    let (reply, response) = oneshot::channel();
    let queued = FundingRequest { target, amount: request.amount, reply };

    state.requests.try_send(queued).map_err(|err| match err {
        mpsc::error::TrySendError::Full(_) => RequestFundsError::Busy,
        mpsc::error::TrySendError::Closed(_) => {
            RequestFundsError::NotReady("the funding worker stopped")
        },
    })?;

    // The worker answers once the note is committed, which takes at least one block interval. A
    // dropped sender means the worker stopped without answering.
    let funded = response
        .await
        .map_err(|_| RequestFundsError::NotReady("the funding worker stopped"))??;

    Ok(Json(funded.into()))
}

/// Checks the requested amount against the configured maximum.
fn validate_amount(amount: u64, maximum: u64) -> Result<(), RequestFundsError> {
    if amount == 0 {
        return Err(RequestFundsError::InvalidAmount);
    }

    if amount > maximum {
        return Err(RequestFundsError::AmountExceedsMaximum { requested: amount, maximum });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use miden_protocol::Word;
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::crypto::merkle::{MerklePath, SparseMerklePath};
    use miden_protocol::note::{Note, NoteInclusionProof, NoteType};
    use miden_protocol::transaction::TransactionId;
    use miden_protocol::utils::serde::Deserializable;
    use miden_standards::note::P2idNote;

    use super::*;

    const MAX_AMOUNT: u64 = 1_000;

    #[test]
    fn a_zero_amount_is_rejected() {
        let err = validate_amount(0, MAX_AMOUNT).unwrap_err();

        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn an_amount_above_the_maximum_is_rejected() {
        validate_amount(MAX_AMOUNT, MAX_AMOUNT).expect("the maximum itself is allowed");

        let err = validate_amount(MAX_AMOUNT + 1, MAX_AMOUNT).unwrap_err();

        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }

    /// The response must carry the note in full: the node does not store the details of a private
    /// note, so the requester cannot fetch them anywhere else.
    #[test]
    fn response_contains_private_note() {
        let faucet_id = FungibleAsset::mock_issuer();
        let note: Note = P2idNote::builder()
            .sender(faucet_id)
            .target(faucet_id)
            .serial_number(Word::from([3u32; 4]))
            .note_type(NoteType::Private)
            .asset(FungibleAsset::new(faucet_id, 42).unwrap())
            .build()
            .unwrap()
            .into();
        let inclusion_proof = NoteInclusionProof::new(
            7.into(),
            3,
            SparseMerklePath::try_from(MerklePath::new(vec![Word::from([1u32; 4])])).unwrap(),
        )
        .unwrap();
        let transaction_id = TransactionId::from_raw(Word::from([9u32; 4]));

        let response = RequestFundsResponse::from(FundedNote {
            note: note.clone(),
            inclusion_proof: inclusion_proof.clone(),
            transaction_id,
        });

        let decoded_note = Note::read_from_bytes(&hex::decode(&response.note).unwrap()).unwrap();
        let decoded_proof =
            NoteInclusionProof::read_from_bytes(&hex::decode(&response.inclusion_proof).unwrap())
                .unwrap();
        let decoded_id =
            TransactionId::read_from_bytes(&hex::decode(&response.transaction_id).unwrap())
                .unwrap();

        assert_eq!(decoded_note.id(), note.id());
        assert_eq!(decoded_note.assets(), note.assets());
        assert_eq!(decoded_note.recipient(), note.recipient());
        assert_eq!(decoded_proof.location(), inclusion_proof.location());
        assert_eq!(decoded_id, transaction_id);
    }
}
