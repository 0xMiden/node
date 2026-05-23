use std::sync::Arc;

use miden_node_proto::decode::{
    convert_digests_to_words,
    read_account_id,
    read_account_ids,
    read_block_range,
    read_root,
};
use miden_node_proto::generated::store::rpc_server;
use miden_node_proto::generated::{self as proto};
use miden_node_utils::limiter::{
    QueryParamAccountIdLimit,
    QueryParamLimiter,
    QueryParamNoteIdLimit,
    QueryParamNoteTagLimit,
    QueryParamNullifierPrefixLimit,
};
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::NoteId;
use tonic::{Request, Response, Status};
use tracing::{debug, info};

use crate::COMPONENT;
use crate::errors::{
    GetAccountError,
    GetBlockByNumberError,
    GetNoteScriptByRootError,
    GetNotesByIdError,
    NoteSyncError,
    SyncAccountStorageMapsError,
    SyncAccountVaultError,
    SyncChainMmrError,
    SyncNullifiersError,
    SyncTransactionsError,
};
use crate::server::api::{StoreApi, internal_error};
use crate::server::replica::{
    BlockSubscriptionStream,
    GuardedStream,
    ProofSubscriptionStream,
    build_block_stream,
    build_proof_stream,
};
use crate::state::Finality;

// CLIENT ENDPOINTS
// ================================================================================================

#[tonic::async_trait]
impl rpc_server::Rpc for StoreApi {
    type BlockSubscriptionStream = BlockSubscriptionStream;
    type ProofSubscriptionStream = ProofSubscriptionStream;

    async fn block_subscription(
        &self,
        request: Request<proto::rpc::BlockSubscriptionRequest>,
    ) -> Result<Response<Self::BlockSubscriptionStream>, Status> {
        let permit = Arc::clone(&self.block_subscription_semaphore)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("maximum block subscriptions reached"))?;

        let from = BlockNumber::from(request.into_inner().block_from);

        let stream = build_block_stream(
            from,
            self.block_cache.clone(),
            self.committed_tip_rx.clone(),
            Arc::clone(&self.state),
        );
        let stream: Self::BlockSubscriptionStream = Box::pin(GuardedStream::new(stream, permit));
        Ok(Response::new(stream))
    }

    async fn proof_subscription(
        &self,
        request: Request<proto::rpc::ProofSubscriptionRequest>,
    ) -> Result<Response<Self::ProofSubscriptionStream>, Status> {
        let permit = Arc::clone(&self.proof_subscription_semaphore)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("maximum proof subscriptions reached"))?;

        let from = BlockNumber::from(request.into_inner().block_from);

        let stream = build_proof_stream(
            from,
            self.proof_cache.clone(),
            self.proven_tip_rx.clone(),
            Arc::clone(&self.state),
        );
        let stream: Self::ProofSubscriptionStream = Box::pin(GuardedStream::new(stream, permit));
        Ok(Response::new(stream))
    }

    /// Returns block header for the specified block number.
    ///
    /// If the block number is not provided, block header for the latest block is returned.
    async fn get_block_header_by_number(
        &self,
        request: Request<proto::rpc::BlockHeaderByNumberRequest>,
    ) -> Result<Response<proto::rpc::BlockHeaderByNumberResponse>, Status> {
        self.get_block_header_by_number_inner(request).await
    }

    /// Returns nullifiers that match the specified prefixes and have been consumed.
    ///
    /// Currently the only supported prefix length is 16 bits.
    async fn sync_nullifiers(
        &self,
        request: Request<proto::rpc::SyncNullifiersRequest>,
    ) -> Result<Response<proto::rpc::SyncNullifiersResponse>, Status> {
        let request = request.into_inner();

        if request.prefix_len != 16 {
            return Err(SyncNullifiersError::InvalidPrefixLength(request.prefix_len).into());
        }

        // Validate nullifier prefix list size before querying state.
        check::<QueryParamNullifierPrefixLimit>(request.nullifiers.len())?;

        let block_range =
            read_block_range::<SyncNullifiersError>(request.block_range, "SyncNullifiersRequest")?
                .into_inclusive_range::<SyncNullifiersError>()?;

        let (nullifiers, block_num) = self
            .state
            .sync_nullifiers(request.prefix_len, request.nullifiers, block_range)
            .await
            .map_err(SyncNullifiersError::from)?;

        let nullifiers = nullifiers
            .into_iter()
            .map(|nullifier_info| proto::rpc::sync_nullifiers_response::NullifierUpdate {
                nullifier: Some(nullifier_info.nullifier.into()),
                block_num: nullifier_info.block_num.as_u32(),
            })
            .collect();

        let chain_tip = self.state.chain_tip(Finality::Committed).await;

        Ok(Response::new(proto::rpc::SyncNullifiersResponse {
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: block_num.as_u32(),
            }),
            nullifiers,
        }))
    }

    /// Returns info which can be used by the client to sync note state.
    async fn sync_notes(
        &self,
        request: Request<proto::rpc::SyncNotesRequest>,
    ) -> Result<Response<proto::rpc::SyncNotesResponse>, Status> {
        let request = request.into_inner();

        let block_range =
            read_block_range::<NoteSyncError>(request.block_range, "SyncNotesRequest")?
                .into_inclusive_range::<NoteSyncError>()?;

        let chain_tip = self.state.chain_tip(Finality::Committed).await;
        if *block_range.end() > chain_tip {
            Err(NoteSyncError::FutureBlock { chain_tip, block_to: *block_range.end() })?;
        }

        // Validate note tags count
        check::<QueryParamNoteTagLimit>(request.note_tags.len())?;

        let (results, last_block_checked) =
            self.state.sync_notes(request.note_tags, block_range).await?;

        let blocks = results
            .into_iter()
            .map(|(state, mmr_proof)| proto::rpc::sync_notes_response::NoteSyncBlock {
                block_header: Some(state.block_header.into()),
                mmr_path: Some(mmr_proof.merkle_path().clone().into()),
                notes: state.notes.into_iter().map(Into::into).collect(),
            })
            .collect();

        Ok(Response::new(proto::rpc::SyncNotesResponse {
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: last_block_checked.as_u32(),
            }),
            blocks,
        }))
    }

    /// Returns chain MMR updates within a block range.
    async fn sync_chain_mmr(
        &self,
        request: Request<proto::rpc::SyncChainMmrRequest>,
    ) -> Result<Response<proto::rpc::SyncChainMmrResponse>, Status> {
        let request = request.into_inner();

        let current_client_block_height = BlockNumber::from(request.current_client_block_height);

        // Determine finality level of the tip to sync to or default to the committed tip.
        let sync_target = match request.finality_level() {
            proto::rpc::FinalityLevel::Committed | proto::rpc::FinalityLevel::Unspecified => {
                self.state.chain_tip(Finality::Committed).await
            },
            proto::rpc::FinalityLevel::Proven => self.state.chain_tip(Finality::Proven).await,
        };

        if current_client_block_height > sync_target {
            Err(SyncChainMmrError::FutureBlock {
                chain_tip: sync_target,
                current_client_block_height,
            })?;
        }
        let block_range = current_client_block_height..=sync_target;
        let (mmr_delta, block_header, block_signature) =
            self.state.sync_chain_mmr(block_range.clone()).await.map_err(internal_error)?;

        Ok(Response::new(proto::rpc::SyncChainMmrResponse {
            block_range: Some(proto::rpc::BlockRange {
                block_from: block_range.start().as_u32(),
                block_to: block_range.end().as_u32(),
            }),
            mmr_delta: Some(mmr_delta.into()),
            block_header: Some(block_header.into()),
            block_signature: Some(block_signature.into()),
        }))
    }

    /// Returns a list of [`Note`]s for the specified [`NoteId`]s.
    ///
    /// If the list is empty or no [`Note`] matched the requested [`NoteId`] and empty list is
    /// returned.
    async fn get_notes_by_id(
        &self,
        request: Request<proto::note::NoteIdList>,
    ) -> Result<Response<proto::note::CommittedNoteList>, Status> {
        info!(target: COMPONENT, ?request);

        let note_ids = request.into_inner().ids;

        // Validate note IDs count
        check::<QueryParamNoteIdLimit>(note_ids.len())?;

        let note_ids: Vec<Word> = convert_digests_to_words::<GetNotesByIdError, _>(note_ids)?;

        let note_ids: Vec<NoteId> = note_ids.into_iter().map(NoteId::from_raw).collect();

        let notes = self
            .state
            .get_notes_by_id(note_ids)
            .await
            .map_err(GetNotesByIdError::from)?
            .into_iter()
            .map(Into::into)
            .collect();

        Ok(Response::new(proto::note::CommittedNoteList { notes }))
    }

    async fn get_block_by_number(
        &self,
        request: Request<proto::blockchain::BlockRequest>,
    ) -> Result<Response<proto::blockchain::MaybeBlock>, Status> {
        let request = request.into_inner();

        debug!(target: COMPONENT, ?request);

        // Load block from state.
        let block_num = BlockNumber::from(request.block_num);
        let block = self.state.load_block(block_num).await.map_err(GetBlockByNumberError::from)?;

        // Load proof from state.
        let proof = if request.include_proof.unwrap_or_default() {
            self.state.load_proof(block_num).await.map_err(GetBlockByNumberError::from)?
        } else {
            None
        };

        Ok(Response::new(proto::blockchain::MaybeBlock { block, proof }))
    }

    async fn get_account(
        &self,
        request: Request<proto::rpc::AccountRequest>,
    ) -> Result<Response<proto::rpc::AccountResponse>, Status> {
        debug!(target: COMPONENT, ?request);
        let request = request.into_inner();
        let account_request = request.try_into().map_err(GetAccountError::DeserializationFailed)?;

        let account_data = self.state.get_account(account_request).await?;

        Ok(Response::new(account_data.into()))
    }

    async fn sync_account_vault(
        &self,
        request: Request<proto::rpc::SyncAccountVaultRequest>,
    ) -> Result<Response<proto::rpc::SyncAccountVaultResponse>, Status> {
        let request = request.into_inner();

        let account_id: AccountId = read_account_id::<
            proto::rpc::SyncAccountVaultRequest,
            SyncAccountVaultError,
        >(request.account_id)?;

        if !account_id.is_public() {
            return Err(SyncAccountVaultError::AccountNotPublic(account_id).into());
        }

        let block_range = read_block_range::<SyncAccountVaultError>(
            request.block_range,
            "SyncAccountVaultRequest",
        )?
        .into_inclusive_range::<SyncAccountVaultError>()?;

        let (last_included_block, updates) = self
            .state
            .sync_account_vault(account_id, block_range)
            .await
            .map_err(SyncAccountVaultError::from)?;

        let updates = updates
            .into_iter()
            .map(|update| {
                let vault_key: Word = update.vault_key.into();
                proto::rpc::AccountVaultUpdate {
                    vault_key: Some(vault_key.into()),
                    asset: update.asset.map(Into::into),
                    block_num: update.block_num.as_u32(),
                }
            })
            .collect();

        let chain_tip = self.state.chain_tip(Finality::Committed).await;

        Ok(Response::new(proto::rpc::SyncAccountVaultResponse {
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: last_included_block.as_u32(),
            }),
            updates,
        }))
    }

    /// Returns storage map updates for the specified account within a block range.
    ///
    /// Supports cursor-based pagination for large storage maps.
    async fn sync_account_storage_maps(
        &self,
        request: Request<proto::rpc::SyncAccountStorageMapsRequest>,
    ) -> Result<Response<proto::rpc::SyncAccountStorageMapsResponse>, Status> {
        let request = request.into_inner();

        let account_id = read_account_id::<
            proto::rpc::SyncAccountStorageMapsRequest,
            SyncAccountStorageMapsError,
        >(request.account_id)?;

        if !account_id.is_public() {
            Err(SyncAccountStorageMapsError::AccountNotPublic(account_id))?;
        }

        let block_range = read_block_range::<SyncAccountStorageMapsError>(
            request.block_range,
            "SyncAccountStorageMapsRequest",
        )?
        .into_inclusive_range::<SyncAccountStorageMapsError>()?;

        let storage_maps_page = self
            .state
            .sync_account_storage_maps(account_id, block_range)
            .await
            .map_err(SyncAccountStorageMapsError::from)?;

        let updates = storage_maps_page
            .values
            .into_iter()
            .map(|map_value| proto::rpc::StorageMapUpdate {
                slot_name: map_value.slot_name.to_string(),
                key: Some(map_value.key.into()),
                value: Some(map_value.value.into()),
                block_num: map_value.block_num.as_u32(),
            })
            .collect();

        let chain_tip = self.state.chain_tip(Finality::Committed).await;

        Ok(Response::new(proto::rpc::SyncAccountStorageMapsResponse {
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: storage_maps_page.last_block_included.as_u32(),
            }),
            updates,
        }))
    }

    async fn status(
        &self,
        _request: Request<()>,
    ) -> Result<Response<proto::rpc::StoreStatus>, Status> {
        Ok(Response::new(proto::rpc::StoreStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            status: "connected".to_string(),
            chain_tip: self.state.chain_tip(Finality::Committed).await.as_u32(),
        }))
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

    async fn are_network_accounts(
        &self,
        request: Request<proto::account::AccountIdList>,
    ) -> Result<Response<proto::store::NetworkAccountIdSubset>, Status> {
        let ids = read_account_ids::<Status, _>(request.into_inner().account_ids)?;
        let subset = self.state.network_accounts_subset(&ids).await?;
        let network_account_ids = subset.into_iter().map(proto::account::AccountId::from).collect();
        Ok(Response::new(proto::store::NetworkAccountIdSubset { network_account_ids }))
    }

    async fn sync_transactions(
        &self,
        request: Request<proto::rpc::SyncTransactionsRequest>,
    ) -> Result<Response<proto::rpc::SyncTransactionsResponse>, Status> {
        debug!(target: COMPONENT, request = ?request);

        let request = request.into_inner();

        let block_range = read_block_range::<SyncTransactionsError>(
            request.block_range,
            "SyncTransactionsRequest",
        )?
        .into_inclusive_range::<SyncTransactionsError>()?;

        let account_ids: Vec<AccountId> =
            read_account_ids::<SyncTransactionsError, _>(request.account_ids)?;

        // Validate account IDs count
        check::<QueryParamAccountIdLimit>(account_ids.len())?;

        let (last_block_included, transaction_records_db) = self
            .state
            .sync_transactions(account_ids, block_range.clone())
            .await
            .map_err(SyncTransactionsError::from)?;

        // Convert database TransactionRecords directly to proto TransactionRecords. All data needed
        // for the proto TransactionHeader is stored in the transactions table.
        let transactions: Vec<_> = transaction_records_db
            .into_iter()
            .map(crate::db::TransactionRecord::into_proto)
            .collect();

        let chain_tip = self.state.chain_tip(Finality::Committed).await;

        Ok(Response::new(proto::rpc::SyncTransactionsResponse {
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: last_block_included.as_u32(),
            }),
            transactions,
        }))
    }
}

// LIMIT HELPERS
// ================================================================================================

/// Formats an "Out of range" error
fn out_of_range_error<E: core::fmt::Display>(err: E) -> Status {
    Status::out_of_range(err.to_string())
}

/// Check, but don't repeat ourselves mapping the error
fn check<Q: QueryParamLimiter>(n: usize) -> Result<(), Status> {
    <Q as QueryParamLimiter>::check(n).map_err(out_of_range_error)
}
