use std::collections::BTreeSet;
use std::time::Duration;

use futures::{Stream, StreamExt};
use miden_node_proto::clients::{Builder, StoreNtxBuilderClient};
use miden_node_proto::decode::ConversionResultExt;
use miden_node_proto::domain::account::{AccountDetails, AccountResponse};
use miden_node_proto::errors::ConversionError;
use miden_node_proto::generated::{self as proto};
use miden_protocol::Word;
use miden_protocol::account::{
    AccountCode,
    AccountId,
    PartialAccount,
    PartialStorage,
    StorageMapKey,
    StorageMapWitness,
    StorageSlotName,
};
use miden_protocol::asset::{AssetVaultKey, AssetWitness, PartialVault};
use miden_protocol::block::{BlockNumber, SignedBlock};
use miden_protocol::crypto::merkle::smt::SmtProof;
use miden_protocol::note::NoteScript;
use miden_protocol::transaction::AccountInputs;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use thiserror::Error;
use tracing::{info, instrument};
use url::Url;

use crate::COMPONENT;

// STORE CLIENT
// ================================================================================================

/// Interface to the store's ntx-builder gRPC API.
///
/// Essentially just a thin wrapper around the generated gRPC client which improves type safety.
#[derive(Clone, Debug)]
pub struct StoreClient {
    inner: StoreNtxBuilderClient,
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
            .connect_lazy::<StoreNtxBuilderClient>();

        Self { inner: store }
    }

    /// Opens a block subscription stream starting from `block_from` (inclusive).
    ///
    /// On `Unavailable` errors the connection is retried with exponential backoff. The returned
    /// stream yields decoded [`SignedBlock`]s as they arrive.
    #[instrument(target = COMPONENT, name = "store.client.block_subscription_with_retry", skip_all, err)]
    pub async fn block_subscription_with_retry(
        &self,
        block_from: BlockNumber,
    ) -> Result<impl Stream<Item = Result<SignedBlock, StoreError>> + Send + 'static, StoreError>
    {
        let mut retry_counter = 0u32;
        loop {
            match self.block_subscription(block_from).await {
                Err(StoreError::GrpcClientError(err)) if err.code() == tonic::Code::Unavailable => {
                    let backoff = Duration::from_millis(500)
                        .saturating_mul(1 << retry_counter.min(6))
                        .min(Duration::from_secs(30));

                    tracing::warn!(
                        ?backoff,
                        %retry_counter,
                        %err,
                        "store connection failed while subscribing to blocks, retrying"
                    );

                    retry_counter += 1;
                    tokio::time::sleep(backoff).await;
                },
                result => return result,
            }
        }
    }

    async fn block_subscription(
        &self,
        block_from: BlockNumber,
    ) -> Result<impl Stream<Item = Result<SignedBlock, StoreError>> + Send + 'static, StoreError>
    {
        let request = proto::store::BlockSubscriptionRequest { block_from: block_from.as_u32() };

        let stream = self.inner.clone().block_subscription(request).await?.into_inner();

        Ok(stream.map(|res| {
            let signed = res.map_err(StoreError::GrpcClientError)?;
            SignedBlock::read_from_bytes(&signed.block).map_err(|err| {
                StoreError::DeserializationError(ConversionError::from(err).context("SignedBlock"))
            })
        }))
    }

    /// Get the inputs for an account at a given block number from the store.
    ///
    /// Retrieves account details from the store. The retrieved details are limited to the account
    /// code, account header, and storage header. The vault and storage slots are not required for
    /// the purposes of the NTX Builder.
    #[instrument(target = COMPONENT, name = "store.client.get_account_inputs", skip_all, err)]
    pub async fn get_account_inputs(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
    ) -> Result<AccountInputs, StoreError> {
        // Construct proto request.
        let proto_request = proto::rpc::AccountRequest {
            account_id: Some(proto::account::AccountId { id: account_id.to_bytes() }),
            block_num: Some(block_num.into()),
            // Request account code, account header, and storage header in order to build minimal
            // partial account.
            details: Some(proto::rpc::account_request::AccountDetailRequest {
                code_commitment: Some(Word::default().into()),
                asset_vault_commitment: None,
                storage_maps: vec![],
            }),
        };

        // Make the gRPC call.
        let proto_response = self.inner.clone().get_account(proto_request).await?.into_inner();

        // Convert proto response to domain type.
        let account_response =
            AccountResponse::try_from(proto_response).map_err(StoreError::DeserializationError)?;

        // Build partial account.
        let account_details = account_response
            .details
            .ok_or(StoreError::MissingDetails("account details".into()))?;
        let partial_account = build_minimal_foreign_account(&account_details)
            .map_err(StoreError::DeserializationError)?;

        Ok(AccountInputs::new(partial_account, account_response.witness))
    }

    #[instrument(target = COMPONENT, name = "store.client.get_note_script_by_root", skip_all, err)]
    pub async fn get_note_script_by_root(
        &self,
        root: Word,
    ) -> Result<Option<NoteScript>, StoreError> {
        let request = proto::note::NoteScriptRoot { root: Some(root.into()) };

        let script = self.inner.clone().get_note_script_by_root(request).await?.into_inner().script;

        script
            .map(NoteScript::try_from)
            .transpose()
            .map_err(StoreError::DeserializationError)
    }

    #[instrument(target = COMPONENT, name = "store.client.get_vault_asset_witnesses", skip_all, err)]
    pub async fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        vault_keys: BTreeSet<AssetVaultKey>,
        block_num: Option<BlockNumber>,
    ) -> Result<Vec<AssetWitness>, StoreError> {
        // Construct proto request.
        let request = proto::store::VaultAssetWitnessesRequest {
            account_id: Some(proto::account::AccountId { id: account_id.to_bytes() }),
            vault_keys: vault_keys
                .into_iter()
                .map(|key| {
                    let word: Word = key.into();
                    word.into()
                })
                .collect(),
            block_num: block_num.map(|num| num.as_u32()),
        };

        // Make the gRPC request.
        let witness_proto =
            self.inner.clone().get_vault_asset_witnesses(request).await?.into_inner();

        // Convert the response to domain type.
        let mut asset_witnesses = Vec::new();
        for asset_witness in witness_proto.asset_witnesses {
            let smt_opening = asset_witness.proof.ok_or_else(|| {
                StoreError::MalformedResponse("missing proof in vault asset witness".to_string())
            })?;
            let proof: SmtProof = smt_opening
                .try_into()
                .context("proof")
                .map_err(StoreError::DeserializationError)?;
            let witness = AssetWitness::new(proof)
                .map_err(|err| StoreError::DeserializationError(ConversionError::from(err)))?;

            asset_witnesses.push(witness);
        }

        Ok(asset_witnesses)
    }

    #[instrument(target = COMPONENT, name = "store.client.get_storage_map_witness", skip_all, err)]
    pub async fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        slot_name: StorageSlotName,
        map_key: StorageMapKey,
        block_num: Option<BlockNumber>,
    ) -> Result<StorageMapWitness, StoreError> {
        // Construct proto request.
        let request = proto::store::StorageMapWitnessRequest {
            account_id: Some(proto::account::AccountId { id: account_id.to_bytes() }),
            map_key: Some(map_key.into()),
            slot_name: slot_name.to_string(),
            block_num: block_num.map(|num| num.as_u32()),
        };

        // Make the request to the store.
        let witness_proto = self.inner.clone().get_storage_map_witness(request).await?.into_inner();

        // Convert the response to domain type.
        let witness_proto = witness_proto.witness.ok_or_else(|| {
            StoreError::MalformedResponse("missing storage map witness in response".to_string())
        })?;

        let smt_opening = witness_proto.proof.ok_or_else(|| {
            StoreError::MalformedResponse("missing proof in storage map witness".to_string())
        })?;

        let proof: SmtProof = smt_opening
            .try_into()
            .context("proof")
            .map_err(StoreError::DeserializationError)?;

        // Create the storage map witness using the proof and raw map key.
        let witness = StorageMapWitness::new(proof, [map_key]).map_err(|_err| {
            StoreError::MalformedResponse("failed to create storage map witness".to_string())
        })?;

        Ok(witness)
    }
}

// STORE ERROR
// =================================================================================================

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("gRPC client error")]
    GrpcClientError(#[from] tonic::Status),
    #[error("malformed response from store: {0}")]
    MalformedResponse(String),
    #[error("failed to parse response")]
    DeserializationError(#[from] ConversionError),
    #[error("missing details: {0}")]
    MissingDetails(String),
}

// HELPERS
// =================================================================================================

/// Builds a minimal partial account from the provided account details.
///
/// The partial account is built without storage maps or an asset vault. This is intended to be used
/// to retrieve foreign account data during transaction execution.
pub fn build_minimal_foreign_account(
    account_details: &AccountDetails,
) -> Result<PartialAccount, ConversionError> {
    // Derive account code.
    let account_code_bytes = account_details.account_code.as_ref().ok_or_else(|| {
        ConversionError::missing_field::<proto::rpc::account_response::AccountDetails>(
            "account_code",
        )
    })?;
    let account_code = AccountCode::read_from_bytes(account_code_bytes)?;

    // Derive partial storage. Storage maps are not required for foreign accounts.
    let partial_storage = PartialStorage::new(account_details.storage_details.header.clone(), [])?;

    // Derive partial vault from vault root only.
    let partial_vault = PartialVault::new(account_details.account_header.vault_root());

    // Construct partial account.
    let partial_account = PartialAccount::new(
        account_details.account_header.id(),
        account_details.account_header.nonce(),
        account_code,
        partial_storage,
        partial_vault,
        None,
    )?;
    Ok(partial_account)
}
