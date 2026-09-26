use std::collections::HashSet;

use miden_node_proto::domain::account::{
    AccountDetailRequest,
    AccountDetails,
    AccountRequest,
    AccountResponse,
    AccountStorageDetails,
    AccountStorageMapDetails,
    AccountStorageRequest,
    AccountVaultDetails,
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
        account_request: AccountRequest,
    ) -> Result<AccountResponse, GetAccountError> {
        let AccountRequest { block_num, account_id, details } = account_request;

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

        Ok(AccountResponse {
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
        validate_storage_map_requests(
            account_id,
            scoped_block,
            &storage_requests,
            &storage_header,
        )?;

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

/// Validates that each requested slot exists in the account storage and is a map slot.
///
/// A request for a missing slot or a value slot is a client error. The forest has no map root for
/// such a slot, so a forest lookup cannot tell this case apart from a missing storage root.
fn validate_storage_map_requests(
    account_id: AccountId,
    block_num: ScopedBlockNum,
    requests: &[StorageMapRequest],
    storage_header: &AccountStorageHeader,
) -> Result<(), GetAccountError> {
    for StorageMapRequest { slot_name, .. } in requests {
        let slot = storage_header.find_slot_header_by_name(slot_name).ok_or_else(|| {
            GetAccountError::StorageSlotNotFound {
                account_id,
                slot_name: slot_name.clone(),
                block_num: *block_num,
            }
        })?;
        if slot.slot_type() != StorageSlotType::Map {
            return Err(GetAccountError::StorageSlotNotMap {
                account_id,
                slot_name: slot_name.clone(),
                block_num: *block_num,
            });
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use miden_node_utils::fee::{test_fee_params, test_protocol_config};
    use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
    use miden_protocol::account::component::AccountComponentMetadata;
    use miden_protocol::account::{
        Account,
        AccountBuilder,
        AccountComponent,
        AccountType,
        StorageMap,
        StorageMapKey,
        StorageSlot,
    };
    use miden_protocol::block::ValidatorConfig;
    use miden_protocol::testing::random_secret_key::random_secret_key;
    use miden_protocol::{EMPTY_WORD, Word};
    use miden_standards::account::auth::{Approver, AuthSingleSig};
    use miden_standards::code_builder::CodeBuilder;

    use super::*;
    use crate::GenesisState;
    use crate::state::State;

    fn value_slot_name() -> StorageSlotName {
        StorageSlotName::new("test::value").unwrap()
    }

    fn map_slot_name() -> StorageSlotName {
        StorageSlotName::new("test::map").unwrap()
    }

    /// Returns a public account with one value slot and one map slot.
    fn account_with_value_and_map_slots() -> Account {
        let storage_map = StorageMap::with_entries(vec![(
            StorageMapKey::from_index(1),
            Word::from([1u32, 2, 3, 4]),
        )])
        .unwrap();
        let component_storage = vec![
            StorageSlot::with_value(value_slot_name(), Word::from([5u32, 6, 7, 8])),
            StorageSlot::with_map(map_slot_name(), storage_map),
        ];
        let component_code = CodeBuilder::default()
            .compile_component_code(
                "test::interface",
                "@account_procedure pub proc test push.1 end",
            )
            .unwrap();
        let component = AccountComponent::new(
            component_code,
            component_storage,
            AccountComponentMetadata::new("test"),
        )
        .unwrap();

        AccountBuilder::new([3u8; 32])
            .account_type(AccountType::Public)
            .with_component(component)
            .with_component(AuthSingleSig::new(Approver::new(
                PublicKeyCommitment::from(EMPTY_WORD),
                AuthScheme::Falcon512Poseidon2,
            )))
            .build_existing()
            .unwrap()
    }

    fn bootstrap_store(path: &std::path::Path, account: Account) {
        let signer = random_secret_key();
        let genesis_block = GenesisState::new(
            vec![account],
            test_fee_params(),
            1,
            ValidatorConfig::new(vec![signer.public_key()], 1)
                .expect("validator config should be valid"),
            test_protocol_config(),
        )
        .into_block()
        .expect("genesis block should be created");

        State::bootstrap(genesis_block, path).expect("store should bootstrap");
    }

    fn storage_request(account_id: AccountId, request: StorageMapRequest) -> AccountRequest {
        AccountRequest {
            account_id,
            block_num: None,
            details: Some(AccountDetailRequest {
                code_commitment: None,
                asset_vault_commitment: None,
                storage_request: AccountStorageRequest::Explicit(vec![request]),
            }),
        }
    }

    /// A storage request that names a missing slot, or a value slot, is a client error. It must not
    /// surface as a database inconsistency.
    #[tokio::test(flavor = "multi_thread")]
    async fn explicit_storage_request_for_an_invalid_slot_is_a_request_error() {
        let account = account_with_value_and_map_slots();
        let account_id = account.id();
        let data_directory = tempfile::tempdir().expect("tempdir should be created");
        bootstrap_store(data_directory.path(), account);
        let (state, _block_writer, _proof_writer) = State::for_tests(data_directory.path()).await;

        let missing_slot = StorageSlotName::new("test::missing").unwrap();
        let map_keys = SlotData::MapKeys(vec![StorageMapKey::from_index(1)]);

        for slot_data in [SlotData::All, map_keys.clone()] {
            let request = StorageMapRequest {
                slot_name: missing_slot.clone(),
                slot_data: slot_data.clone(),
            };
            let result = state.view().get_account(storage_request(account_id, request)).await;
            assert!(
                matches!(
                    &result,
                    Err(GetAccountError::StorageSlotNotFound { account_id: id, slot_name, .. })
                        if *id == account_id && *slot_name == missing_slot
                ),
                "missing slot with {slot_data:?} must be a request error, got {:?}",
                result.map(|_| ())
            );

            let request = StorageMapRequest {
                slot_name: value_slot_name(),
                slot_data: slot_data.clone(),
            };
            let result = state.view().get_account(storage_request(account_id, request)).await;
            assert!(
                matches!(
                    &result,
                    Err(GetAccountError::StorageSlotNotMap { account_id: id, slot_name, .. })
                        if *id == account_id && *slot_name == value_slot_name()
                ),
                "value slot with {slot_data:?} must be a request error, got {:?}",
                result.map(|_| ())
            );
        }

        // Requests for the map slot still succeed.
        for slot_data in [SlotData::All, map_keys] {
            let request = StorageMapRequest { slot_name: map_slot_name(), slot_data };
            let response = state
                .view()
                .get_account(storage_request(account_id, request))
                .await
                .expect("map slot request should succeed");
            let details = response.details.expect("details should be returned");
            assert_eq!(details.storage_details.map_details.len(), 1);
            assert_eq!(details.storage_details.map_details[0].slot_name, map_slot_name());
        }
    }
}
