use std::collections::BTreeSet;

use miden_crypto::merkle::smt::SmtProof;
use miden_node_proto::decode::{read_account_id, read_root};
use miden_node_proto::errors::ConversionError;
use miden_node_proto::generated as proto;
use miden_node_proto::generated::store::{BlockSubscriptionRequest, ntx_builder_server};
use miden_protocol::account::{StorageMapKey, StorageSlotName};
use miden_protocol::asset::AssetVaultKey;
use tonic::{Request, Response, Status};
use tracing::debug;

use crate::COMPONENT;
use crate::errors::{GetAccountError, GetNoteScriptByRootError, GetWitnessesError};
use crate::server::api::{StoreApi, internal_error, invalid_argument};
use crate::server::replica::BlockSubscriptionStream;
use crate::state::Finality;

// NTX BUILDER ENDPOINTS
// ================================================================================================

#[tonic::async_trait]
impl ntx_builder_server::NtxBuilder for StoreApi {
    type BlockSubscriptionStream = BlockSubscriptionStream;

    /// See [`StoreApi::block_subscription_inner`] — same semantics as
    /// `StoreReplica::BlockSubscription`. Declared on this service so the ntx-builder can drive
    /// its committed-block subscription through a single client.
    async fn block_subscription(
        &self,
        request: Request<BlockSubscriptionRequest>,
    ) -> Result<Response<Self::BlockSubscriptionStream>, Status> {
        self.block_subscription_inner(request)
    }

    async fn get_account(
        &self,
        request: Request<proto::rpc::AccountRequest>,
    ) -> Result<Response<proto::rpc::AccountResponse>, Status> {
        debug!(target: COMPONENT, ?request);
        let request = request.into_inner();
        let account_request = request.try_into().map_err(GetAccountError::DeserializationFailed)?;

        let proof = self.state.get_account(account_request).await?;

        Ok(Response::new(proof.into()))
    }

    async fn get_note_script_by_root(
        &self,
        request: Request<proto::note::NoteScriptRoot>,
    ) -> Result<Response<proto::rpc::MaybeNoteScript>, Status> {
        debug!(target: COMPONENT, request = ?request);

        let root =
            read_root::<GetNoteScriptByRootError>(request.into_inner().root, "NoteScriptRoot")?;

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
        const MAX_VAULT_KEYS: usize = 100;

        let request = request.into_inner();

        // Sanity check the number of vault keys in the request
        if request.vault_keys.len() > MAX_VAULT_KEYS {
            tracing::warn!(
                limit=%MAX_VAULT_KEYS,
                request=%request.vault_keys.len(),
                account.id=%request.account_id.unwrap_or_default(),
                "maximum vault key limit exceeded",
            );

            return Err(Status::invalid_argument(format!(
                "number of vault keys in request cannot exceed {MAX_VAULT_KEYS}"
            )));
        }

        // Read account ID.
        let account_id = read_account_id::<
            proto::store::VaultAssetWitnessesRequest,
            GetWitnessesError,
        >(request.account_id)
        .map_err(invalid_argument)?;

        // Read vault keys.
        let vault_keys = request
            .vault_keys
            .into_iter()
            .map(|key_digest| {
                let word = read_root::<GetWitnessesError>(Some(key_digest), "VaultKey")
                    .map_err(invalid_argument)?;
                AssetVaultKey::try_from(word).map_err(|e| {
                    invalid_argument(GetWitnessesError::DeserializationFailed(
                        ConversionError::from(e),
                    ))
                })
            })
            .collect::<Result<BTreeSet<_>, Status>>()?;

        // Read block number from request, use latest if not provided.
        let block_num = if let Some(num) = request.block_num {
            num.into()
        } else {
            self.state.chain_tip(Finality::Committed).await
        };

        // Retrieve the asset witnesses.
        let asset_witnesses = self
            .state
            .get_vault_asset_witnesses(account_id, block_num, vault_keys)
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
            read_account_id::<proto::store::StorageMapWitnessRequest, GetWitnessesError>(
                request.account_id,
            )
            .map_err(invalid_argument)?;

        // Read the map key.
        let map_key = read_root::<GetWitnessesError>(request.map_key, "MapKey")
            .map(StorageMapKey::new)
            .map_err(invalid_argument)?;

        // Read the slot name.
        let slot_name = StorageSlotName::new(request.slot_name).map_err(|err| {
            tonic::Status::invalid_argument(format!("Invalid storage slot name: {err}"))
        })?;

        // Read the block number, use latest if not provided.
        let block_num = if let Some(num) = request.block_num {
            num.into()
        } else {
            self.state.chain_tip(Finality::Committed).await
        };

        // Retrieve the storage map witness.
        let storage_witness = self
            .state
            .get_storage_map_witness(account_id, &slot_name, block_num, map_key)
            .map_err(internal_error)?;

        // Convert StorageMapWitness to protobuf format by extracting witness data.
        let proof: SmtProof = storage_witness.into();
        Ok(Response::new(proto::store::StorageMapWitnessResponse {
            witness: Some(proto::store::storage_map_witness_response::StorageWitness {
                key: Some(map_key.into()),
                proof: Some(proof.into()),
            }),
            block_num: self.state.chain_tip(Finality::Committed).await.as_u32(),
        }))
    }
}
