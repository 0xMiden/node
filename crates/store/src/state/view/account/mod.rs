use std::collections::HashSet;

use miden_node_proto::domain::account::{
    AccountDetailRequest,
    AccountDetails,
    AccountStorageDetails,
    AccountStorageMapDetails,
    AccountStorageRequest,
    AccountVaultDetails,
    GetAccountRequest,
    GetAccountResponse,
    SlotData,
    StorageMapEntries,
    StorageMapRequest,
};
use miden_node_tracing::miden_instrument;
use miden_protocol::account::{AccountId, AccountStorageHeader, StorageSlotName, StorageSlotType};
use miden_protocol::block::BlockNumber;
use miden_protocol::block::account_tree::AccountWitness;

use super::{ScopedBlockNum, StateView};
use crate::COMPONENT;
use crate::account_state_forest::AccountStorageMapResult;
use crate::errors::{DatabaseError, GetAccountError};

impl StateView {
    /// Returns an account witness and optionally account details at a specific block.
    ///
    /// The witness is a Merkle proof of inclusion in the account tree, proving the account's
    /// state commitment. If `details` is requested, the method also returns the account's code,
    /// vault assets, and storage data. Account details are only available for public accounts.
    ///
    /// If `block_num` is provided, returns the state at that historical block; otherwise, returns
    /// the latest state. Note that historical states are only available for recent blocks close
    /// to the chain tip.
    #[miden_instrument(
        target = COMPONENT,
    )]
    pub async fn get_account(
        &self,
        get_account_request: GetAccountRequest,
    ) -> Result<GetAccountResponse, GetAccountError> {
        let GetAccountRequest { block_num, account_id, details } = get_account_request;

        if details.is_some() && !account_id.is_public() {
            return Err(GetAccountError::AccountNotPublic(account_id));
        }

        let (scoped_block, witness) = self.get_account_witness(block_num, account_id).await?;

        let details = if let Some(request) = details {
            Some(
                self.fetch_public_account_details(account_id, scoped_block, &witness, request)
                    .await?,
            )
        } else {
            None
        };

        Ok(GetAccountResponse {
            block_num: *scoped_block,
            witness,
            details,
        })
    }

    /// Returns an account witness (Merkle proof of inclusion in the account tree) together with
    /// the resolved block as a scoped block number.
    ///
    /// If `block_num` is provided, returns the witness at that historical block; otherwise,
    /// returns the witness at the latest block. The tree resolution doubles as the tip
    /// validation, so the returned block is ready for block-bounded database queries.
    #[miden_instrument(
        target = COMPONENT,
    )]
    async fn get_account_witness(
        &self,
        block_num: Option<BlockNumber>,
        account_id: AccountId,
    ) -> Result<(ScopedBlockNum, AccountWitness), GetAccountError> {
        // Historical query: scope the requested block up front — a block beyond this view's tip is
        // unknown, so a missing tree entry below can only mean it was pruned.
        if let Some(requested_block) = block_num {
            let scoped_block = self
                .scope_block(requested_block)
                .ok_or(GetAccountError::UnknownBlock(requested_block))?;
            let witness = self
                .with_inner_read_blocking(|inner_state| {
                    inner_state.account_tree.open_at(account_id, *scoped_block)
                })
                .ok_or(GetAccountError::BlockPruned(*scoped_block))?;
            Ok((scoped_block, witness))
        } else {
            // Latest query: the tree's latest state is the view's tip.
            let witness = self.with_inner_read_blocking(|inner_state| {
                inner_state.account_tree.open_latest(account_id)
            });
            Ok((self.tip(), witness))
        }
    }

    /// Returns storage map details from the forest for a specific account and storage slot.
    ///
    /// The forest can only be used if all hashed keys in the storage map are known in the
    /// reverse-key LRU cache. If any hashed key is unknown, the method returns `Ok(None)` to signal
    /// that the caller should fall back to reconstructing the storage map details from the
    /// database.
    #[miden_instrument(
        target = COMPONENT,
    )]
    fn get_storage_map_details_from_forest(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
        block_num: ScopedBlockNum,
    ) -> Result<Option<AccountStorageMapDetails>, DatabaseError> {
        self.with_forest_read_blocking(|forest| {
            match forest
                .get_storage_map_details_for_all_entries(account_id, slot_name.clone(), *block_num)
                .map_err(DatabaseError::MerkleError)?
            {
                AccountStorageMapResult::NotFound => Err(DatabaseError::StorageRootNotFound {
                    account_id,
                    slot_name: slot_name.to_string(),
                    block_num: *block_num,
                }),
                AccountStorageMapResult::Details(details) => Ok(Some(details)),
                AccountStorageMapResult::CannotReconstructKeysFromCache => Ok(None),
            }
        })
    }

    /// Returns vault details by reconstructing the vault from the database.
    async fn reconstruct_vault_details_from_db(
        &self,
        account_id: AccountId,
        block_num: ScopedBlockNum,
    ) -> Result<AccountVaultDetails, DatabaseError> {
        let assets = self.db.select_account_vault_at_block(account_id, block_num).await?;

        if assets.len() > AccountVaultDetails::MAX_RETURN_ENTRIES {
            return Ok(AccountVaultDetails::LimitExceeded);
        }

        let keys = assets.iter().map(miden_protocol::asset::Asset::id);

        // The reverse-key caches are shared between the writer and all snapshots, so caching via
        // the current snapshot's forest is visible everywhere.
        self.with_forest_read_blocking(|forest| {
            forest
                .vault_key_cache
                .put_many(keys.into_iter().map(|raw_key| (raw_key.hash(), raw_key)));
        });

        Ok(AccountVaultDetails::from_assets(assets))
    }

    /// Returns storage map details by reconstructing the storage map from the database.
    async fn reconstruct_storage_map_details_from_db(
        &self,
        account_id: AccountId,
        slot_name: StorageSlotName,
        block_num: ScopedBlockNum,
    ) -> Result<AccountStorageMapDetails, DatabaseError> {
        let details = self
            .db
            .reconstruct_storage_map_from_db(
                account_id,
                slot_name,
                block_num,
                Some(AccountStorageMapDetails::MAX_RETURN_ENTRIES),
            )
            .await?;

        if let StorageMapEntries::AllEntries(entries) = &details.entries {
            self.with_forest_read_blocking(|forest| {
                forest.cache_storage_map_keys(entries.iter().map(|(raw_key, _)| *raw_key));
            });
        }

        Ok(details)
    }

    /// Fetches the account details (code, vault, storage) for a public account at the specified
    /// block.
    ///
    /// This method queries the database to fetch the account state and processes the detail
    /// request to return only the requested information.
    ///
    /// For specific key queries (`SlotData::MapKeys`), the forest is used to provide SMT proofs.
    /// Returns an error if the forest doesn't have data for the requested slot.
    /// All-entries queries (`SlotData::All`) use the forest when all hashed keys are known in the
    /// reverse-key LRU cache, otherwise they fall back to database reconstruction.
    #[miden_instrument(
        target = COMPONENT,
    )]
    async fn fetch_public_account_details(
        &self,
        account_id: AccountId,
        scoped_block: ScopedBlockNum,
        witness: &AccountWitness,
        detail_request: AccountDetailRequest,
    ) -> Result<AccountDetails, GetAccountError> {
        let AccountDetailRequest {
            code_commitment,
            asset_vault_commitment,
            storage_request,
        } = detail_request;

        if !account_id.is_public() {
            return Err(GetAccountError::AccountNotPublic(account_id));
        }

        // Query account header and storage header together in a single DB call
        let (account_header, storage_header) = self
            .db
            .select_account_header_with_storage_header_at_block(account_id, scoped_block)
            .await?
            .ok_or(GetAccountError::AccountNotFound(account_id, *scoped_block))?;

        let should_apply_response_budget =
            matches!(&storage_request, AccountStorageRequest::AllStorageMaps);
        let storage_requests = expand_account_storage_request(storage_request, &storage_header);

        let account_code = match code_commitment {
            Some(commitment) if commitment == account_header.code_commitment() => None,
            Some(_) => {
                self.db
                    .select_account_code_by_commitment(account_header.code_commitment())
                    .await?
            },
            None => None,
        };

        // Query account state forest for vault details on commitment mismatch.
        //
        // The forest can only reconstruct the vault if all hashed vault keys are known in the
        // reverse-key LRU cache. If any hashed key is unknown, the forest returns `None` and we
        // fall back to reconstructing the vault details from the database.
        let vault_details = match asset_vault_commitment {
            Some(commitment) if commitment == account_header.vault_root() => {
                AccountVaultDetails::empty()
            },
            Some(_) => {
                let forest_details = self.with_forest_read_blocking(|forest| {
                    forest.get_vault_details(account_id, *scoped_block).map_err(|err| {
                        DatabaseError::DataCorrupted(format!(
                            "failed to reconstruct vault for account {account_id} at block {}: {err}",
                            *scoped_block,
                        ))
                    })
                })?;

                match forest_details {
                    Some(details) => details,
                    None => {
                        self.reconstruct_vault_details_from_db(account_id, scoped_block).await?
                    },
                }
            },
            None => AccountVaultDetails::empty(),
        };

        // Split storage map requests into two categories:
        // - slots with explicit keys (including proofs)
        // - slots with "all entries"
        let mut storage_map_details =
            Vec::<AccountStorageMapDetails>::with_capacity(storage_requests.len());
        let mut map_keys_requests = Vec::new();
        let mut all_entries_requests = Vec::new();
        let mut storage_request_slots = Vec::with_capacity(storage_requests.len());

        for (index, StorageMapRequest { slot_name, slot_data }) in
            storage_requests.into_iter().enumerate()
        {
            storage_request_slots.push(slot_name.clone());
            match slot_data {
                SlotData::MapKeys(keys) => {
                    map_keys_requests.push((index, slot_name, keys));
                },
                SlotData::All => {
                    all_entries_requests.push((index, slot_name));
                },
            }
        }

        let mut storage_map_details_by_index = vec![None; storage_request_slots.len()];

        // Handle slots with explicit key requests
        if !map_keys_requests.is_empty() {
            self.with_forest_read_blocking(|forest| {
                for (index, slot_name, keys) in map_keys_requests {
                    let details = forest
                        .get_storage_map_details_for_keys(
                            account_id,
                            slot_name.clone(),
                            *scoped_block,
                            keys,
                        )
                        .ok_or_else(|| DatabaseError::StorageRootNotFound {
                            account_id,
                            slot_name: slot_name.to_string(),
                            block_num: *scoped_block,
                        })?
                        .map_err(DatabaseError::MerkleError)?;
                    storage_map_details_by_index[index] = Some(details);
                }
                Ok::<(), DatabaseError>(())
            })?;
        }

        // Handle slots with "all entries" requests
        for (index, slot_name) in all_entries_requests {
            let details = match self.get_storage_map_details_from_forest(
                account_id,
                &slot_name,
                scoped_block,
            )? {
                Some(details) => details,
                None => {
                    self.reconstruct_storage_map_details_from_db(
                        account_id,
                        slot_name,
                        scoped_block,
                    )
                    .await?
                },
            };
            storage_map_details_by_index[index] = Some(details);
        }

        for (details, slot_name) in
            storage_map_details_by_index.into_iter().zip(storage_request_slots.iter())
        {
            let details = details.ok_or_else(|| DatabaseError::StorageRootNotFound {
                account_id,
                slot_name: slot_name.to_string(),
                block_num: *scoped_block,
            })?;
            storage_map_details.push(details);
        }

        // In case of an "all storage maps" request we have to be careful: even with the per-slot
        // limit of [`AccountStorageMapDetails::MAX_RETURN_ENTRIES`] we might go over the response
        // size limit. Here we make sure that we're within that limit by potentially truncating the
        // response.
        if should_apply_response_budget {
            return Ok(apply_all_storage_maps_response_budget(
                *scoped_block,
                witness,
                account_header,
                account_code,
                vault_details,
                storage_header,
                storage_map_details,
                storage_request_slots,
                MAX_ALL_STORAGE_MAPS_RESPONSE_PAYLOAD_WITH_BUDGET_RESERVED_FOR_LIMIT_EXCEEDED_SLOTS,
            ));
        }

        Ok(AccountDetails {
            account_header,
            account_code,
            vault_details,
            storage_details: AccountStorageDetails {
                header: storage_header,
                map_details: storage_map_details,
            },
        })
    }
}

// HELPERS
// ================================================================================================

/// Expand [`AccountStorageRequest`] to a vector of slot requests.
fn expand_account_storage_request(
    storage_request: AccountStorageRequest,
    storage_header: &AccountStorageHeader,
) -> Vec<StorageMapRequest> {
    match storage_request {
        AccountStorageRequest::None => Vec::new(),
        AccountStorageRequest::Explicit(requests) => requests,
        AccountStorageRequest::AllStorageMaps => storage_header
            .slots()
            .filter(|slot| slot.slot_type() == StorageSlotType::Map)
            .map(|slot| StorageMapRequest {
                slot_name: slot.name().clone(),
                slot_data: SlotData::All,
            })
            .collect(),
    }
}

mod response_budget;
use response_budget::{
    MAX_ALL_STORAGE_MAPS_RESPONSE_PAYLOAD_WITH_BUDGET_RESERVED_FOR_LIMIT_EXCEEDED_SLOTS,
    apply_all_storage_maps_response_budget,
};

// NETWORK ACCOUNT CLASSIFICATION
// ================================================================================================

impl StateView {
    /// Filters `account_ids` down to the subset classified as network accounts.
    pub async fn filter_network_accounts(
        &self,
        account_ids: &[AccountId],
    ) -> Result<HashSet<AccountId>, DatabaseError> {
        self.db.select_network_accounts_subset(account_ids.to_vec()).await
    }
}
