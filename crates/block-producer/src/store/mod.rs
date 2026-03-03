use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::num::NonZeroU32;

use itertools::Itertools;
use miden_node_proto::clients::{Builder, StoreBlockProducerClient};
use miden_node_proto::domain::batch::BatchInputs;
use miden_node_proto::errors::{ConversionError, MissingFieldHelper};
use miden_node_proto::{AccountState, generated as proto};
use miden_node_utils::formatting::format_opt;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::batch::OrderedBatches;
use miden_protocol::block::{BlockHeader, BlockInputs, BlockNumber, SignedBlock};
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::ProvenTransaction;
use miden_protocol::utils::Serializable;
use tracing::{debug, info, instrument};
use url::Url;

use crate::COMPONENT;
use crate::errors::StoreError;

// TRANSACTION INPUTS
// ================================================================================================

/// Information needed from the store to verify a transaction.
#[derive(Debug)]
pub struct TransactionInputs {
    /// Account ID
    pub account_id: AccountId,
    /// The account commitment in the store corresponding to tx's account ID
    pub account_commitment: Option<Word>,
    /// Maps each consumed notes' nullifier to block number, where the note is consumed.
    ///
    /// We use `NonZeroU32` as the wire format uses 0 to encode none.
    pub nullifiers: HashMap<Nullifier, Option<NonZeroU32>>,
    /// Unauthenticated note commitments which are present in the store.
    ///
    /// These are notes which were committed _after_ the transaction was created.
    pub found_unauthenticated_notes: HashSet<Word>,
    /// The current block height.
    pub current_block_height: BlockNumber,
}

impl Display for TransactionInputs {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let nullifiers = self
            .nullifiers
            .iter()
            .map(|(k, v)| format!("{k}: {}", format_opt(v.as_ref())))
            .join(", ");

        let nullifiers = if nullifiers.is_empty() {
            "None".to_owned()
        } else {
            format!("{{ {nullifiers} }}")
        };

        f.write_fmt(format_args!(
            "{{ account_id: {}, account_commitment: {}, nullifiers: {} }}",
            self.account_id,
            format_opt(self.account_commitment.as_ref()),
            nullifiers
        ))
    }
}

impl TryFrom<proto::store::TransactionInputs> for TransactionInputs {
    type Error = ConversionError;

    fn try_from(response: proto::store::TransactionInputs) -> Result<Self, Self::Error> {
        let AccountState { account_id, account_commitment } = response
            .account_state
            .ok_or(proto::store::TransactionInputs::missing_field(stringify!(account_state)))?
            .try_into()?;

        let mut nullifiers = HashMap::new();
        for nullifier_record in response.nullifiers {
            let nullifier = nullifier_record
                .nullifier
                .ok_or(
                    proto::store::transaction_inputs::NullifierTransactionInputRecord::missing_field(
                        stringify!(nullifier),
                    ),
                )?
                .try_into()?;

            // Note that this intentionally maps 0 to None as this is the definition used in
            // protobuf.
            nullifiers.insert(nullifier, NonZeroU32::new(nullifier_record.block_num));
        }

        let found_unauthenticated_notes = response
            .found_unauthenticated_notes
            .into_iter()
            .map(Word::try_from)
            .collect::<Result<_, ConversionError>>()?;

        let current_block_height = response.block_height.into();

        Ok(Self {
            account_id,
            account_commitment,
            nullifiers,
            found_unauthenticated_notes,
            current_block_height,
        })
    }
}

// STORE CLIENT
// ================================================================================================

/// Interface to the store's block-producer gRPC API.
///
/// Essentially just a thin wrapper around the generated gRPC client which improves type safety.
#[derive(Clone, Debug)]
pub struct StoreClient {
    client: StoreBlockProducerClient,
}

impl StoreClient {
    /// Creates a new store client with a lazy connection.
    pub fn new(store_url: Url) -> Self {
        info!(target: COMPONENT, store_endpoint = %store_url, "Initializing store client");

        let store = Builder::new(store_url)
            .without_tls()
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<StoreBlockProducerClient>();

        Self { client: store }
    }

    /// Returns the latest block's header from the store.
    #[instrument(target = COMPONENT, name = "store.client.latest_header", skip_all, err)]
    pub async fn latest_header(&self) -> Result<BlockHeader, StoreError> {
        let response = self
            .client
            .clone()
            .get_block_header_by_number(tonic::Request::new(
                proto::rpc::BlockHeaderByNumberRequest::default(),
            ))
            .await?
            .into_inner()
            .block_header
            .ok_or(miden_node_proto::generated::blockchain::BlockHeader::missing_field(
                "block_header",
            ))?;

        BlockHeader::try_from(response).map_err(Into::into)
    }

    #[instrument(target = COMPONENT, name = "store.client.get_tx_inputs", skip_all, err)]
    pub async fn get_tx_inputs(
        &self,
        proven_tx: &ProvenTransaction,
    ) -> Result<TransactionInputs, StoreError> {
        let message = proto::store::TransactionInputsRequest {
            account_id: Some(proven_tx.account_id().into()),
            nullifiers: proven_tx.nullifiers().map(Into::into).collect(),
            unauthenticated_notes: proven_tx
                .unauthenticated_notes()
                .map(|note| note.commitment().into())
                .collect(),
        };

        info!(target: COMPONENT, tx_id = %proven_tx.id().to_hex());
        debug!(target: COMPONENT, ?message);

        let request = tonic::Request::new(message);
        let response = self.client.clone().get_transaction_inputs(request).await?.into_inner();

        debug!(target: COMPONENT, ?response);

        if !response.new_account_id_prefix_is_unique.unwrap_or(true) {
            debug_assert!(
                proven_tx.account_update().initial_state_commitment().is_empty(),
                "account id prefix uniqueness should not be validated unless transaction creates a new account"
            );
            return Err(StoreError::DuplicateAccountIdPrefix(proven_tx.account_id()));
        }

        let tx_inputs: TransactionInputs = response.try_into()?;

        if tx_inputs.account_id != proven_tx.account_id() {
            return Err(StoreError::MalformedResponse(format!(
                "incorrect account id returned from store. Got: {}, expected: {}",
                tx_inputs.account_id,
                proven_tx.account_id()
            )));
        }

        debug!(target: COMPONENT, %tx_inputs);

        Ok(tx_inputs)
    }

    #[instrument(target = COMPONENT, name = "store.client.get_block_inputs", skip_all, err)]
    pub async fn get_block_inputs(
        &self,
        updated_accounts: impl Iterator<Item = AccountId> + Send,
        created_nullifiers: impl Iterator<Item = Nullifier> + Send,
        unauthenticated_notes: impl Iterator<Item = Word> + Send,
        reference_blocks: impl Iterator<Item = BlockNumber> + Send,
    ) -> Result<BlockInputs, StoreError> {
        let request = tonic::Request::new(proto::store::BlockInputsRequest {
            account_ids: updated_accounts.map(Into::into).collect(),
            nullifiers: created_nullifiers.map(proto::primitives::Digest::from).collect(),
            unauthenticated_notes: unauthenticated_notes
                .map(proto::primitives::Digest::from)
                .collect(),
            reference_blocks: reference_blocks.map(|block_num| block_num.as_u32()).collect(),
        });

        let store_response = self.client.clone().get_block_inputs(request).await?.into_inner();

        store_response.try_into().map_err(Into::into)
    }

    #[instrument(target = COMPONENT, name = "store.client.get_batch_inputs", skip_all, err)]
    pub async fn get_batch_inputs(
        &self,
        block_references: impl Iterator<Item = (BlockNumber, Word)> + Send,
        note_commitments: impl Iterator<Item = Word> + Send,
    ) -> Result<BatchInputs, StoreError> {
        let request = tonic::Request::new(proto::store::BatchInputsRequest {
            reference_blocks: block_references.map(|(block_num, _)| block_num.as_u32()).collect(),
            note_commitments: note_commitments.map(proto::primitives::Digest::from).collect(),
        });

        let store_response = self.client.clone().get_batch_inputs(request).await?.into_inner();

        store_response.try_into().map_err(Into::into)
    }

    #[instrument(target = COMPONENT, name = "store.client.apply_block", skip_all, err)]
    pub async fn apply_block(
        &self,
        ordered_batches: &OrderedBatches,
        signed_block: &SignedBlock,
    ) -> Result<(), StoreError> {
        let request = tonic::Request::new(proto::store::ApplyBlockRequest {
            ordered_batches: ordered_batches.to_bytes(),
            block: Some(signed_block.into()),
        });

        self.client.clone().apply_block(request).await.map(|_| ()).map_err(Into::into)
    }
}
