use std::collections::BTreeSet;
use std::ops::RangeInclusive;
use std::time::Duration;

use miden_node_proto::clients::{Builder, StoreNtxBuilderClient};
use miden_node_proto::domain::account::{AccountDetails, AccountResponse, NetworkAccountId};
use miden_node_proto::domain::note::NetworkNote;
use miden_node_proto::errors::ConversionError;
use miden_node_proto::generated::rpc::BlockRange;
use miden_node_proto::generated::{self as proto};
use miden_node_proto::try_convert;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::Word;
use miden_protocol::account::{
    Account,
    AccountCode,
    AccountId,
    PartialAccount,
    PartialStorage,
    StorageMapWitness,
    StorageSlotName,
};
use miden_protocol::asset::{AssetVaultKey, AssetWitness, PartialVault};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::merkle::mmr::{Forest, MmrPeaks, PartialMmr};
use miden_protocol::crypto::merkle::smt::SmtProof;
use miden_protocol::note::NoteScript;
use miden_protocol::transaction::AccountInputs;
use miden_tx::utils::{Deserializable, Serializable};
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

    /// Returns the block header and MMR peaks at the current chain tip.
    #[instrument(target = COMPONENT, name = "store.client.get_latest_blockchain_data_with_retry", skip_all, err)]
    pub async fn get_latest_blockchain_data_with_retry(
        &self,
    ) -> Result<Option<(BlockHeader, PartialMmr)>, StoreError> {
        let mut retry_counter = 0;
        loop {
            match self.get_latest_blockchain_data().await {
                Err(StoreError::GrpcClientError(err)) => {
                    // Exponential backoff with base 500ms and max 30s.
                    let backoff = Duration::from_millis(500)
                        .saturating_mul(1 << retry_counter.min(6))
                        .min(Duration::from_secs(30));

                    tracing::warn!(
                        ?backoff,
                        %retry_counter,
                        %err,
                        "store connection failed while fetching latest blockchain data, retrying"
                    );

                    retry_counter += 1;
                    tokio::time::sleep(backoff).await;
                },
                result => return result,
            }
        }
    }

    #[instrument(target = COMPONENT, name = "store.client.get_latest_blockchain_data", skip_all, err)]
    async fn get_latest_blockchain_data(
        &self,
    ) -> Result<Option<(BlockHeader, PartialMmr)>, StoreError> {
        let request = tonic::Request::new(proto::blockchain::MaybeBlockNumber::default());

        let response = self.inner.clone().get_current_blockchain_data(request).await?.into_inner();

        match response.current_block_header {
            // There are new blocks compared to the builder's latest state
            Some(block) => {
                let peaks = try_convert(response.current_peaks).collect::<Result<_, _>>()?;
                let header =
                    BlockHeader::try_from(block).map_err(StoreError::DeserializationError)?;

                let peaks = MmrPeaks::new(Forest::new(header.block_num().as_usize()), peaks)
                    .map_err(|_| {
                        StoreError::MalformedResponse(
                            "returned peaks are not valid for the sent request".into(),
                        )
                    })?;

                let partial_mmr = PartialMmr::from_peaks(peaks);

                Ok(Some((header, partial_mmr)))
            },
            // No new blocks were created, return
            None => Ok(None),
        }
    }

    #[instrument(target = COMPONENT, name = "store.client.get_network_account", skip_all, err)]
    pub async fn get_network_account(
        &self,
        account_id: NetworkAccountId,
    ) -> Result<Option<Account>, StoreError> {
        let request = proto::account::AccountId::from(account_id.inner());

        let store_response = self
            .inner
            .clone()
            .get_network_account_details_by_id(request)
            .await?
            .into_inner()
            .details;

        // we only care about the case where the account returns and is actually a network account,
        // which implies details being public, so OK to error otherwise
        let account = match store_response.map(|acc| acc.details) {
            Some(Some(details)) => Some(Account::read_from_bytes(&details).map_err(|err| {
                StoreError::DeserializationError(ConversionError::deserialization_error(
                    "account", err,
                ))
            })?),
            _ => None,
        };

        Ok(account)
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
        let partial_account = build_minimal_foreign_account(&account_details)?;

        Ok(AccountInputs::new(partial_account, account_response.witness))
    }

    /// Returns the list of unconsumed network notes for a specific network account up to a
    /// specified block.
    #[instrument(target = COMPONENT, name = "store.client.get_unconsumed_network_notes", skip_all, err)]
    pub async fn get_unconsumed_network_notes(
        &self,
        network_account_id: NetworkAccountId,
        block_num: u32,
    ) -> Result<Vec<NetworkNote>, StoreError> {
        // Upper bound of each note is ~10KB. Limit page size to ~10MB.
        const PAGE_SIZE: u64 = 1024;

        let mut all_notes = Vec::new();
        let mut page_token: Option<u64> = None;

        let mut store_client = self.inner.clone();
        loop {
            let req = proto::store::UnconsumedNetworkNotesRequest {
                page_token,
                page_size: PAGE_SIZE,
                account_id: Some(network_account_id.inner().into()),
                block_num,
            };
            let resp = store_client.get_unconsumed_network_notes(req).await?.into_inner();

            all_notes.reserve(resp.notes.len());
            for note in resp.notes {
                all_notes.push(NetworkNote::try_from(note)?);
            }

            match resp.next_token {
                Some(token) => page_token = Some(token),
                None => break,
            }
        }

        Ok(all_notes)
    }

    /// Streams network account IDs to the provided sender.
    ///
    /// This method is designed to be run in a background task, sending accounts to the main event
    /// loop as they are loaded. This allows the ntx-builder to start processing mempool events
    /// without waiting for all accounts to be preloaded.
    pub async fn stream_network_account_ids(
        &self,
        sender: tokio::sync::mpsc::Sender<NetworkAccountId>,
    ) -> Result<(), StoreError> {
        let mut block_range = BlockNumber::GENESIS..=BlockNumber::MAX;

        while let Some(next_start) = self.load_accounts_page(block_range, &sender).await? {
            block_range = next_start..=BlockNumber::MAX;
        }

        Ok(())
    }

    /// Loads a single page of network accounts and submits them to the sender.
    ///
    /// Returns the next block number to fetch from, or `None` if the chain tip has been reached.
    #[instrument(target = COMPONENT, name = "store.client.load_accounts_page", skip_all, err)]
    async fn load_accounts_page(
        &self,
        block_range: RangeInclusive<BlockNumber>,
        sender: &tokio::sync::mpsc::Sender<NetworkAccountId>,
    ) -> Result<Option<BlockNumber>, StoreError> {
        let (accounts, pagination_info) = self.fetch_network_account_ids_page(block_range).await?;

        let chain_tip = pagination_info.chain_tip;
        let current_height = pagination_info.block_num;

        self.send_accounts_to_channel(accounts, sender).await?;

        if current_height >= chain_tip {
            Ok(None)
        } else {
            Ok(Some(BlockNumber::from(current_height)))
        }
    }

    #[instrument(target = COMPONENT, name = "store.client.fetch_network_account_ids_page", skip_all, err)]
    async fn fetch_network_account_ids_page(
        &self,
        block_range: std::ops::RangeInclusive<BlockNumber>,
    ) -> Result<(Vec<NetworkAccountId>, proto::rpc::PaginationInfo), StoreError> {
        self.fetch_network_account_ids_page_inner(block_range)
            .await
            .inspect_err(|err| tracing::Span::current().set_error(err))
    }

    async fn fetch_network_account_ids_page_inner(
        &self,
        block_range: std::ops::RangeInclusive<BlockNumber>,
    ) -> Result<(Vec<NetworkAccountId>, proto::rpc::PaginationInfo), StoreError> {
        let mut retry_counter = 0u32;

        let response = loop {
            match self
                .inner
                .clone()
                .get_network_account_ids(Into::<BlockRange>::into(block_range.clone()))
                .await
            {
                Ok(response) => break response.into_inner(),
                Err(err) => {
                    // Exponential backoff with base 500ms and max 30s.
                    let backoff = Duration::from_millis(500)
                        .saturating_mul(1 << retry_counter.min(6))
                        .min(Duration::from_secs(30));

                    tracing::warn!(
                        ?backoff,
                        %retry_counter,
                        %err,
                        "store connection failed while fetching committed accounts page, retrying"
                    );

                    retry_counter += 1;
                    tokio::time::sleep(backoff).await;
                },
            }
        };

        let accounts = response
            .account_ids
            .into_iter()
            .map(|account_id| {
                let account_id = AccountId::read_from_bytes(&account_id.id).map_err(|err| {
                    StoreError::DeserializationError(ConversionError::deserialization_error(
                        "account_id",
                        err,
                    ))
                })?;
                NetworkAccountId::try_from(account_id).map_err(|_| {
                    StoreError::MalformedResponse(
                        "account id is not a valid network account".into(),
                    )
                })
            })
            .collect::<Result<Vec<NetworkAccountId>, StoreError>>()?;

        let pagination_info = response.pagination_info.ok_or(
            ConversionError::MissingFieldInProtobufRepresentation {
                entity: "NetworkAccountIdList",
                field_name: "pagination_info",
            },
        )?;

        Ok((accounts, pagination_info))
    }

    #[instrument(
        target = COMPONENT,
        name = "store.client.send_accounts_to_channel",
        skip_all
    )]
    async fn send_accounts_to_channel(
        &self,
        accounts: Vec<NetworkAccountId>,
        sender: &tokio::sync::mpsc::Sender<NetworkAccountId>,
    ) -> Result<(), StoreError> {
        for account in accounts {
            // If the receiver is dropped, stop loading.
            if sender.send(account).await.is_err() {
                tracing::warn!("Account receiver dropped");
                return Ok(());
            }
        }

        Ok(())
    }

    #[instrument(target = COMPONENT, name = "store.client.get_note_script_by_root", skip_all, err)]
    pub async fn get_note_script_by_root(
        &self,
        root: Word,
    ) -> Result<Option<NoteScript>, StoreError> {
        let request = proto::note::NoteRoot { root: Some(root.into()) };

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
            let proof: SmtProof =
                smt_opening.try_into().map_err(StoreError::DeserializationError)?;
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
        map_key: Word,
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

        let proof: SmtProof = smt_opening.try_into().map_err(StoreError::DeserializationError)?;

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
    let account_code_bytes = account_details
        .account_code
        .as_ref()
        .ok_or(ConversionError::AccountCodeMissing)?;
    let account_code = AccountCode::from_bytes(account_code_bytes)?;

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
