use std::collections::BTreeSet;
use std::num::{NonZero, TryFromIntError};

use miden_crypto::merkle::smt::SmtProof;
use miden_node_proto::domain::account::AccountInfo;
use miden_node_proto::generated as proto;
use miden_node_proto::generated::rpc::BlockRange;
use miden_node_proto::generated::store::ntx_builder_server;
use miden_node_utils::ErrorReport;
use miden_protocol::account::StorageSlotName;
use miden_protocol::asset::AssetVaultKey;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Note;
use tonic::{Request, Response, Status};
use tracing::debug;

use crate::COMPONENT;
use crate::db::models::Page;
use crate::errors::{GetNetworkAccountIdsError, GetNoteScriptByRootError, GetWitnessesError};
use crate::server::api::{
    StoreApi,
    internal_error,
    invalid_argument,
    read_account_id,
    read_block_range,
    read_root,
};

// NTX BUILDER ENDPOINTS
// ================================================================================================

#[tonic::async_trait]
impl ntx_builder_server::NtxBuilder for StoreApi {
    /// Returns block header for the specified block number.
    ///
    /// If the block number is not provided, block header for the latest block is returned.
    async fn get_block_header_by_number(
        &self,
        request: Request<proto::rpc::BlockHeaderByNumberRequest>,
    ) -> Result<Response<proto::rpc::BlockHeaderByNumberResponse>, Status> {
        self.get_block_header_by_number_inner(request).await
    }

    /// Returns the chain tip's header and MMR peaks corresponding to that header.
    /// If there are N blocks, the peaks will represent the MMR at block `N - 1`.
    ///
    /// This returns all the blockchain-related information needed for executing transactions
    /// without authenticating notes.
    async fn get_current_blockchain_data(
        &self,
        request: Request<proto::blockchain::MaybeBlockNumber>,
    ) -> Result<Response<proto::store::CurrentBlockchainData>, Status> {
        let block_num = request.into_inner().block_num.map(BlockNumber::from);

        let response = match self
            .state
            .get_current_blockchain_data(block_num)
            .await
            .map_err(internal_error)?
        {
            Some((header, peaks)) => proto::store::CurrentBlockchainData {
                current_peaks: peaks.peaks().iter().map(Into::into).collect(),
                current_block_header: Some(header.into()),
            },
            None => proto::store::CurrentBlockchainData {
                current_peaks: vec![],
                current_block_header: None,
            },
        };

        Ok(Response::new(response))
    }

    async fn get_network_account_details_by_id(
        &self,
        request: Request<proto::account::AccountId>,
    ) -> Result<Response<proto::store::MaybeAccountDetails>, Status> {
        let account_id = read_account_id::<Status>(Some(request.into_inner()))?;

        let account_info: Option<AccountInfo> =
            self.state.get_network_account_details_by_id(account_id).await?;

        Ok(Response::new(proto::store::MaybeAccountDetails {
            details: account_info.map(|acc| (&acc).into()),
        }))
    }

    async fn get_unconsumed_network_notes(
        &self,
        request: Request<proto::store::UnconsumedNetworkNotesRequest>,
    ) -> Result<Response<proto::store::UnconsumedNetworkNotes>, Status> {
        let request = request.into_inner();
        let block_num = BlockNumber::from(request.block_num);
        let account_id = read_account_id::<Status>(request.account_id)?;

        let state = self.state.clone();

        let size =
            NonZero::try_from(request.page_size as usize).map_err(|err: TryFromIntError| {
                invalid_argument(err.as_report_context("invalid page_size"))
            })?;
        let page = Page { token: request.page_token, size };
        // TODO: no need to get the whole NoteRecord here, a NetworkNote wrapper should be created
        // instead
        let (notes, next_page) = state
            .get_unconsumed_network_notes_for_account(account_id, block_num, page)
            .await
            .map_err(internal_error)?;

        let mut network_notes = Vec::with_capacity(notes.len());
        for note in notes {
            // SAFETY: Network notes are filtered in the database, so they should have details;
            // otherwise the state would be corrupted
            let (assets, recipient) = note.details.unwrap().into_parts();
            let note = Note::new(assets, note.metadata, recipient);
            network_notes.push(note.into());
        }

        Ok(Response::new(proto::store::UnconsumedNetworkNotes {
            notes: network_notes,
            next_token: next_page.token,
        }))
    }

    /// Returns network account IDs within the specified block range (based on account creation
    /// block).
    ///
    /// The function may return fewer accounts than exist in the range if the result would exceed
    /// `MAX_RESPONSE_PAYLOAD_BYTES / AccountId::SERIALIZED_SIZE` rows. In this case, the result is
    /// truncated at a block boundary to ensure all accounts from included blocks are returned.
    ///
    /// The response includes pagination info with the last block number that was fully included.
    async fn get_network_account_ids(
        &self,
        request: Request<BlockRange>,
    ) -> Result<Response<proto::store::NetworkAccountIdList>, Status> {
        let request = request.into_inner();

        let mut chain_tip = self.state.latest_block_num().await;
        let block_range =
            read_block_range::<GetNetworkAccountIdsError>(Some(request), "GetNetworkAccountIds")?
                .into_inclusive_range::<GetNetworkAccountIdsError>(&chain_tip)?;

        let (account_ids, mut last_block_included) =
            self.state.get_all_network_accounts(block_range).await.map_err(internal_error)?;

        let account_ids = Vec::from_iter(account_ids.into_iter().map(Into::into));

        if last_block_included > chain_tip {
            last_block_included = chain_tip;
        }

        chain_tip = self.state.latest_block_num().await;

        Ok(Response::new(proto::store::NetworkAccountIdList {
            account_ids,
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: last_block_included.as_u32(),
            }),
        }))
    }

    async fn get_account(
        &self,
        request: Request<proto::rpc::AccountRequest>,
    ) -> Result<Response<proto::rpc::AccountResponse>, Status> {
        debug!(target: COMPONENT, ?request);
        let request = request.into_inner();
        let account_request = request.try_into()?;

        let proof = self.state.get_account(account_request).await?;

        Ok(Response::new(proof.into()))
    }

    async fn get_note_script_by_root(
        &self,
        request: Request<proto::note::NoteRoot>,
    ) -> Result<Response<proto::rpc::MaybeNoteScript>, Status> {
        debug!(target: COMPONENT, request = ?request);

        let root = read_root::<GetNoteScriptByRootError>(request.into_inner().root, "NoteRoot")?;

        let note_script = self
            .state
            .get_note_script_by_root(root)
            .await
            .map_err(GetNoteScriptByRootError::from)?;

        Ok(Response::new(proto::rpc::MaybeNoteScript {
            script: note_script.map(Into::into),
        }))
    }

    async fn get_vault_asset_witnesses(
        &self,
        request: Request<proto::store::VaultAssetWitnessesRequest>,
    ) -> Result<Response<proto::store::VaultAssetWitnessesResponse>, Status> {
        let request = request.into_inner();

        // Read account ID.
        let account_id =
            read_account_id::<GetWitnessesError>(request.account_id).map_err(invalid_argument)?;

        // Read vault keys.
        let vault_keys = request
            .vault_keys
            .into_iter()
            .map(|key_digest| {
                let word = read_root::<GetWitnessesError>(Some(key_digest), "VaultKey")
                    .map_err(invalid_argument)?;
                Ok(AssetVaultKey::new_unchecked(word))
            })
            .collect::<Result<BTreeSet<_>, Status>>()?;

        // Read block number from request, use latest if not provided.
        let block_num = if let Some(num) = request.block_num {
            num.into()
        } else {
            self.state.latest_block_num().await
        };

        // Retrieve the asset witnesses.
        let asset_witnesses = self
            .state
            .get_vault_asset_witnesses(account_id, block_num, vault_keys)
            .await
            .map_err(internal_error)?;

        // Convert AssetWitness to protobuf format by extracting witness data.
        let proto_witnesses = asset_witnesses
            .into_iter()
            .map(|witness| {
                let proof: SmtProof = witness.into();
                proto::store::vault_asset_witnesses_response::VaultAssetWitness {
                    proof: Some(proof.into()),
                }
            })
            .collect();

        Ok(Response::new(proto::store::VaultAssetWitnessesResponse {
            block_num: block_num.as_u32(),
            asset_witnesses: proto_witnesses,
        }))
    }

    async fn get_storage_map_witness(
        &self,
        request: Request<proto::store::StorageMapWitnessRequest>,
    ) -> Result<Response<proto::store::StorageMapWitnessResponse>, Status> {
        let request = request.into_inner();

        // Read the account ID.
        let account_id =
            read_account_id::<GetWitnessesError>(request.account_id).map_err(invalid_argument)?;

        // Read the map key.
        let map_key =
            read_root::<GetWitnessesError>(request.map_key, "MapKey").map_err(invalid_argument)?;

        // Read the slot name.
        let slot_name = StorageSlotName::new(request.slot_name).map_err(|err| {
            tonic::Status::invalid_argument(format!("Invalid storage slot name: {err}"))
        })?;

        // Read the block number, use latest if not provided.
        let block_num = if let Some(num) = request.block_num {
            num.into()
        } else {
            self.state.latest_block_num().await
        };

        // Retrieve the storage map witness.
        let storage_witness = self
            .state
            .get_storage_map_witness(account_id, &slot_name, block_num, map_key)
            .await
            .map_err(internal_error)?;

        // Convert StorageMapWitness to protobuf format by extracting witness data.
        let proof: SmtProof = storage_witness.into();
        Ok(Response::new(proto::store::StorageMapWitnessResponse {
            witness: Some(proto::store::storage_map_witness_response::StorageWitness {
                key: Some(map_key.into()),
                proof: Some(proof.into()),
            }),
            block_num: self.state.latest_block_num().await.as_u32(),
        }))
    }
}
