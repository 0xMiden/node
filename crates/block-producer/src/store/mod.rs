use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::num::NonZeroU32;
use std::sync::Arc;

use itertools::Itertools;
use miden_node_proto::clients::{Builder, StoreBlockProducerClient};
use miden_node_proto::decode::{ConversionResultExt, GrpcDecodeExt};
use miden_node_proto::domain::batch::BatchInputs;
use miden_node_proto::domain::proof_request::BlockProofRequest;
use miden_node_proto::errors::ConversionError;
use miden_node_proto::{AccountState, decode, generated as proto};
use miden_node_store::State;
use miden_node_store::state::Finality;
use miden_node_utils::formatting::format_opt;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::batch::OrderedBatches;
use miden_protocol::block::{BlockHeader, BlockInputs, BlockNumber, SignedBlock};
use miden_protocol::note::{NoteHeader, Nullifier};
use miden_protocol::transaction::ProvenTransaction;
use miden_protocol::utils::serde::Serializable;
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
        let decoder = response.decoder();
        let AccountState { account_id, account_commitment } =
            decode!(decoder, response.account_state)?;

        let mut nullifiers = HashMap::new();
        for nullifier_record in response.nullifiers {
            let decoder = nullifier_record.decoder();
            let nullifier = decode!(decoder, nullifier_record.nullifier)?;

            // Note that this intentionally maps 0 to None as this is the definition used in
            // protobuf.
            nullifiers.insert(nullifier, NonZeroU32::new(nullifier_record.block_num));
        }

        let found_unauthenticated_notes = response
            .found_unauthenticated_notes
            .into_iter()
            .map(Word::try_from)
            .collect::<Result<_, ConversionError>>()
            .context("found_unauthenticated_notes")?;

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

// REMOTE STORE CLIENT
// ================================================================================================

/// gRPC-based interface to the store's block-producer API.
#[derive(Clone, Debug)]
pub(crate) struct RemoteStoreClient {
    client: StoreBlockProducerClient,
}

impl RemoteStoreClient {
    fn new(store_url: Url) -> Self {
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
    #[instrument(target = COMPONENT, name = "store.remote_client.latest_header", skip_all, err)]
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
            .ok_or_else(|| {
                StoreError::DeserializationError(ConversionError::missing_field::<
                    miden_node_proto::generated::blockchain::BlockHeader,
                >("block_header"))
            })?;

        BlockHeader::try_from(response).map_err(StoreError::DeserializationError)
    }

    #[instrument(target = COMPONENT, name = "store.remote_client.get_tx_inputs", skip_all, err)]
    pub async fn get_tx_inputs(
        &self,
        proven_tx: &ProvenTransaction,
    ) -> Result<TransactionInputs, StoreError> {
        let message = proto::store::TransactionInputsRequest {
            account_id: Some(proven_tx.account_id().into()),
            nullifiers: proven_tx.nullifiers().map(Into::into).collect(),
            unauthenticated_notes: proven_tx
                .unauthenticated_notes()
                .map(|note| note.to_commitment().into())
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

    #[instrument(target = COMPONENT, name = "store.remote_client.get_block_inputs", skip_all, err)]
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

        store_response.try_into().map_err(StoreError::DeserializationError)
    }

    #[instrument(target = COMPONENT, name = "store.remote_client.get_batch_inputs", skip_all, err)]
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

        store_response.try_into().map_err(StoreError::DeserializationError)
    }

    #[instrument(target = COMPONENT, name = "store.remote_client.apply_block", skip_all, err)]
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

// LOCAL STORE CLIENT
// ================================================================================================

/// In-process interface to the store's block-producer API, bypassing gRPC.
#[derive(Clone)]
pub(crate) struct LocalStoreClient {
    state: Arc<State>,
}

impl std::fmt::Debug for LocalStoreClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalStoreClient").finish_non_exhaustive()
    }
}

impl LocalStoreClient {
    async fn latest_header(&self) -> Result<BlockHeader, StoreError> {
        let (header, _) = self
            .state
            .get_block_header(None, false)
            .await
            .map_err(|e| StoreError::Internal(e.to_string()))?;

        header.ok_or_else(|| StoreError::Internal("store has no latest block header".into()))
    }

    async fn get_tx_inputs(
        &self,
        proven_tx: &ProvenTransaction,
    ) -> Result<TransactionInputs, StoreError> {
        let account_id = proven_tx.account_id();
        let nullifiers: Vec<Nullifier> = proven_tx.nullifiers().collect();
        let unauthenticated_notes: Vec<Word> =
            proven_tx.unauthenticated_notes().map(NoteHeader::to_commitment).collect();

        let tx_inputs = self
            .state
            .get_transaction_inputs(account_id, &nullifiers, unauthenticated_notes)
            .await
            .map_err(|e| StoreError::Internal(e.to_string()))?;

        if let Some(false) = tx_inputs.new_account_id_prefix_is_unique {
            return Err(StoreError::DuplicateAccountIdPrefix(account_id));
        }

        let current_block_height = self.state.chain_tip(Finality::Committed).await;

        let nullifiers: HashMap<Nullifier, Option<NonZeroU32>> = tx_inputs
            .nullifiers
            .into_iter()
            .map(|info| (info.nullifier, NonZeroU32::new(info.block_num.as_u32())))
            .collect();

        let account_commitment = if tx_inputs.account_commitment.is_empty() {
            None
        } else {
            Some(tx_inputs.account_commitment)
        };

        Ok(TransactionInputs {
            account_id,
            account_commitment,
            nullifiers,
            found_unauthenticated_notes: tx_inputs.found_unauthenticated_notes,
            current_block_height,
        })
    }

    async fn get_block_inputs(
        &self,
        updated_accounts: impl Iterator<Item = AccountId> + Send,
        created_nullifiers: impl Iterator<Item = Nullifier> + Send,
        unauthenticated_notes: impl Iterator<Item = Word> + Send,
        reference_blocks: impl Iterator<Item = BlockNumber> + Send,
    ) -> Result<BlockInputs, StoreError> {
        self.state
            .get_block_inputs(
                updated_accounts.collect(),
                created_nullifiers.collect(),
                unauthenticated_notes.collect(),
                reference_blocks.collect(),
            )
            .await
            .map_err(|e| StoreError::Internal(e.to_string()))
    }

    async fn get_batch_inputs(
        &self,
        block_references: impl Iterator<Item = (BlockNumber, Word)> + Send,
        note_commitments: impl Iterator<Item = Word> + Send,
    ) -> Result<BatchInputs, StoreError> {
        let reference_blocks: BTreeSet<BlockNumber> =
            block_references.map(|(block_num, _)| block_num).collect();
        let note_commitments: BTreeSet<Word> = note_commitments.collect();

        self.state
            .get_batch_inputs(reference_blocks, note_commitments)
            .await
            .map_err(|e| StoreError::Internal(e.to_string()))
    }

    async fn apply_block(
        &self,
        ordered_batches: &OrderedBatches,
        signed_block: &SignedBlock,
    ) -> Result<(), StoreError> {
        // Extract block inputs from the ordered batches (mirrors
        // StoreApi::block_inputs_from_ordered_batches).
        let mut account_ids = BTreeSet::new();
        let mut nullifiers = Vec::new();
        let mut unauthenticated_note_commitments = BTreeSet::new();
        let mut reference_blocks = BTreeSet::new();

        for batch in ordered_batches.as_slice() {
            account_ids.extend(batch.updated_accounts());
            nullifiers.extend(batch.created_nullifiers());
            reference_blocks.insert(batch.reference_block_num());

            for note in batch.input_notes().iter() {
                if let Some(header) = note.header() {
                    unauthenticated_note_commitments.insert(header.to_commitment());
                }
            }
        }

        let block_inputs = self
            .state
            .get_block_inputs(
                account_ids.into_iter().collect(),
                nullifiers,
                unauthenticated_note_commitments,
                reference_blocks,
            )
            .await
            .map_err(|e| StoreError::Internal(e.to_string()))?;

        let proving_inputs = BlockProofRequest {
            tx_batches: ordered_batches.clone(),
            block_header: signed_block.header().clone(),
            block_inputs,
        };

        self.state
            .save_proving_inputs(signed_block.header().block_num(), &proving_inputs)
            .await
            .map_err(|e| StoreError::Internal(e.to_string()))?;

        self.state
            .apply_block(signed_block.clone())
            .await
            .map_err(|e| StoreError::Internal(e.to_string()))
    }
}

// STORE CLIENT
// ================================================================================================

/// Interface to the store's block-producer API.
///
/// Supports two backends: a gRPC client for the legacy out-of-process store, and a direct
/// in-process handle for the embedded sequencer.
#[derive(Clone, Debug)]
#[expect(private_interfaces)]
pub enum StoreClient {
    /// Connects to a remote store over gRPC.
    Remote(Box<RemoteStoreClient>),
    /// Calls an in-process `State` directly, bypassing gRPC.
    Local(LocalStoreClient),
}

impl StoreClient {
    /// Creates a gRPC-backed store client with a lazy connection.
    pub fn new(store_url: Url) -> Self {
        Self::Remote(RemoteStoreClient::new(store_url).into())
    }

    /// Creates an in-process store client backed by the given `State`.
    pub fn new_local(state: Arc<State>) -> Self {
        Self::Local(LocalStoreClient { state })
    }

    /// Returns the latest block's header from the store.
    #[instrument(target = COMPONENT, name = "store.client.latest_header", skip_all, err)]
    pub async fn latest_header(&self) -> Result<BlockHeader, StoreError> {
        match self {
            Self::Remote(c) => c.latest_header().await,
            Self::Local(c) => c.latest_header().await,
        }
    }

    #[instrument(target = COMPONENT, name = "store.client.get_tx_inputs", skip_all, err)]
    pub async fn get_tx_inputs(
        &self,
        proven_tx: &ProvenTransaction,
    ) -> Result<TransactionInputs, StoreError> {
        info!(target: COMPONENT, tx_id = %proven_tx.id().to_hex());
        match self {
            Self::Remote(c) => c.get_tx_inputs(proven_tx).await,
            Self::Local(c) => c.get_tx_inputs(proven_tx).await,
        }
    }

    #[instrument(target = COMPONENT, name = "store.client.get_block_inputs", skip_all, err)]
    pub async fn get_block_inputs(
        &self,
        updated_accounts: impl Iterator<Item = AccountId> + Send,
        created_nullifiers: impl Iterator<Item = Nullifier> + Send,
        unauthenticated_notes: impl Iterator<Item = Word> + Send,
        reference_blocks: impl Iterator<Item = BlockNumber> + Send,
    ) -> Result<BlockInputs, StoreError> {
        match self {
            Self::Remote(c) => {
                c.get_block_inputs(
                    updated_accounts,
                    created_nullifiers,
                    unauthenticated_notes,
                    reference_blocks,
                )
                .await
            },
            Self::Local(c) => {
                c.get_block_inputs(
                    updated_accounts,
                    created_nullifiers,
                    unauthenticated_notes,
                    reference_blocks,
                )
                .await
            },
        }
    }

    #[instrument(target = COMPONENT, name = "store.client.get_batch_inputs", skip_all, err)]
    pub async fn get_batch_inputs(
        &self,
        block_references: impl Iterator<Item = (BlockNumber, Word)> + Send,
        note_commitments: impl Iterator<Item = Word> + Send,
    ) -> Result<BatchInputs, StoreError> {
        match self {
            Self::Remote(c) => c.get_batch_inputs(block_references, note_commitments).await,
            Self::Local(c) => c.get_batch_inputs(block_references, note_commitments).await,
        }
    }

    #[instrument(target = COMPONENT, name = "store.client.apply_block", skip_all, err)]
    pub async fn apply_block(
        &self,
        ordered_batches: &OrderedBatches,
        signed_block: &SignedBlock,
    ) -> Result<(), StoreError> {
        match self {
            Self::Remote(c) => c.apply_block(ordered_batches, signed_block).await,
            Self::Local(c) => c.apply_block(ordered_batches, signed_block).await,
        }
    }
}
