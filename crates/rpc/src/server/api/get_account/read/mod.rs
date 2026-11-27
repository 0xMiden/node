use miden_node_proto::domain::account::{
    AccountDetailRequest,
    AccountDetails,
    AccountStorageDetails,
    AccountStorageMapDetails,
    AccountStorageRequest,
    AccountVaultDetails,
    AccountVaultRequest,
    GetAccountRequest,
    GetAccountResponse,
    SlotData,
    StorageMapEntries,
    StorageMapRequest,
};
use miden_node_store::DatabaseError;
use miden_node_store::read::{AccountStorageMapResult, ReadView};
use miden_node_tracing::instrument;
use miden_protocol::account::{AccountId, AccountStorageHeader, StorageSlotName, StorageSlotType};
use miden_protocol::block::BlockNumber;
use miden_protocol::block::account_tree::AccountWitness;

use super::GetAccountError;

/// Returns an account witness and optionally account details at a specific block.
///
/// The witness is a Merkle proof of inclusion in the account tree, proving the account's state
/// commitment. If `details` is requested, the function also returns the account's code, vault
/// assets, and storage data. Account details are only available for public accounts.
///
/// If `block_num` is provided, returns the state at that historical block; otherwise, returns the
/// state at the snapshot block. Note that historical states are only available for recent blocks
/// close to the chain tip.
#[instrument]
pub(crate) fn get_account(
    view: &ReadView<'_>,
    get_account_request: GetAccountRequest,
) -> Result<GetAccountResponse, GetAccountError> {
    let GetAccountRequest { block_num, account_id, details } = get_account_request;

    if details.is_some() && !account_id.is_public() {
        return Err(GetAccountError::AccountNotPublic(account_id));
    }

    let (block_num, witness) = get_account_witness(view, block_num, account_id)?;

    let details = if let Some(request) = details {
        Some(fetch_public_account_details(view, account_id, block_num, &witness, request)?)
    } else {
        None
    };

    Ok(GetAccountResponse { block_num, witness, details })
}

/// Returns an account witness (Merkle proof of inclusion in the account tree) together with the
/// resolved block.
///
/// If `block_num` is provided, returns the witness at that historical block; otherwise, returns
/// the witness at the snapshot block.
#[instrument]
fn get_account_witness(
    view: &ReadView<'_>,
    block_num: Option<BlockNumber>,
    account_id: AccountId,
) -> Result<(BlockNumber, AccountWitness), GetAccountError> {
    // Historical query: a block beyond the snapshot block is unknown, so a missing tree entry below
    // can only mean it was pruned.
    if let Some(requested_block) = block_num {
        if requested_block > view.snapshot.block_num {
            return Err(GetAccountError::UnknownBlock(requested_block));
        }
        let witness = view
            .snapshot
            .account_tree
            .open_at(account_id, requested_block)
            .ok_or(GetAccountError::BlockPruned(requested_block))?;
        Ok((requested_block, witness))
    } else {
        // Latest query: the tree's latest state is the snapshot block.
        let witness = view.snapshot.account_tree.open_latest(account_id);
        Ok((view.snapshot.block_num, witness))
    }
}

/// Returns storage map details from the forest for a specific account and storage slot.
///
/// The forest can only be used if all hashed keys in the storage map are known in the reverse-key
/// LRU cache. If any hashed key is unknown, the function returns `Ok(None)` to signal that the
/// caller should fall back to reconstructing the storage map details from the database.
#[instrument]
fn get_storage_map_details_from_forest(
    view: &ReadView<'_>,
    account_id: AccountId,
    slot_name: &StorageSlotName,
    block_num: BlockNumber,
) -> Result<Option<AccountStorageMapDetails>, DatabaseError> {
    match view
        .snapshot
        .get_storage_map_details_for_all_entries(account_id, slot_name.clone(), block_num)
        .map_err(DatabaseError::MerkleError)?
    {
        AccountStorageMapResult::NotFound => Err(DatabaseError::StorageRootNotFound {
            account_id,
            slot_name: slot_name.to_string(),
            block_num,
        }),
        AccountStorageMapResult::Details(details) => Ok(Some(details)),
        AccountStorageMapResult::CannotReconstructKeysFromCache => Ok(None),
    }
}

/// Returns vault details by reconstructing the vault from the database.
fn reconstruct_vault_details_from_db(
    view: &ReadView<'_>,
    account_id: AccountId,
    block_num: BlockNumber,
) -> Result<AccountVaultDetails, DatabaseError> {
    let assets = view.tx.select_vault_at_block(account_id, block_num)?;

    if assets.len() > AccountVaultDetails::MAX_RETURN_ENTRIES {
        return Ok(AccountVaultDetails::LimitExceeded);
    }

    view.snapshot
        .cache_vault_keys(assets.iter().map(miden_protocol::asset::Asset::id));

    Ok(AccountVaultDetails::from_assets(assets))
}

/// Returns storage map details by reconstructing the storage map from the database.
fn reconstruct_storage_map_details_from_db(
    view: &ReadView<'_>,
    account_id: AccountId,
    slot_name: StorageSlotName,
    block_num: BlockNumber,
) -> Result<AccountStorageMapDetails, DatabaseError> {
    let details = view.tx.select_storage_map_at_block(
        account_id,
        slot_name,
        block_num,
        AccountStorageMapDetails::MAX_RETURN_ENTRIES,
    )?;

    if let StorageMapEntries::AllEntries(entries) = &details.entries {
        view.snapshot
            .cache_storage_map_keys(entries.iter().map(|(raw_key, _)| *raw_key));
    }

    Ok(details)
}

/// Fetches the account details (code, vault, storage) for a public account at the specified block.
///
/// This function queries the database to fetch the account state and processes the detail request
/// to return only the requested information.
///
/// For specific key queries (`SlotData::MapKeys`), the forest is used to provide SMT proofs.
/// Returns an error if the forest doesn't have data for the requested slot.
/// All-entries queries (`SlotData::All`) use the forest when all hashed keys are known in the
/// reverse-key LRU cache, otherwise they fall back to database reconstruction.
#[instrument]
fn fetch_public_account_details(
    view: &ReadView<'_>,
    account_id: AccountId,
    block_num: BlockNumber,
    witness: &AccountWitness,
    detail_request: AccountDetailRequest,
) -> Result<AccountDetails, GetAccountError> {
    let AccountDetailRequest {
        code_commitment,
        vault_request,
        storage_request,
    } = detail_request;

    if !account_id.is_public() {
        return Err(GetAccountError::AccountNotPublic(account_id));
    }

    // Query account header and storage header together in a single DB call
    let (account_header, storage_header) = view
        .tx
        .select_account_header_with_storage_header(account_id, block_num)?
        .ok_or(GetAccountError::AccountNotFound(account_id, block_num))?;

    let should_apply_response_budget =
        matches!(&storage_request, AccountStorageRequest::AllStorageMaps);
    let storage_requests = expand_account_storage_request(storage_request, &storage_header);
    validate_storage_map_requests(account_id, block_num, &storage_requests, &storage_header)?;

    let account_code = match code_commitment {
        Some(commitment) if commitment == account_header.code_commitment() => None,
        Some(_) => view.tx.select_account_code(account_header.code_commitment())?,
        None => None,
    };

    let vault_details = match vault_request {
        AccountVaultRequest::All(commitment) if commitment == account_header.vault_root() => {
            AccountVaultDetails::empty()
        },
        AccountVaultRequest::All(_) => {
            let forest_details =
                view.snapshot.get_vault_details(account_id, block_num).map_err(|err| {
                    DatabaseError::DataCorrupted(format!(
                        "failed to reconstruct vault for account {account_id} at block {block_num}: {err}",
                    ))
                })?;

            match forest_details {
                Some(details) => details,
                None => reconstruct_vault_details_from_db(view, account_id, block_num)?,
            }
        },
        AccountVaultRequest::None => AccountVaultDetails::empty(),
        AccountVaultRequest::Assets(asset_ids) => view
            .snapshot
            .get_vault_details_for_assets(account_id, block_num, asset_ids)
            .map_err(|err| {
                DatabaseError::DataCorrupted(format!(
                    "failed to open vault for account {account_id} at block {block_num}: {err}",
                ))
            })?,
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
    for (index, slot_name, keys) in map_keys_requests {
        let details = view
            .snapshot
            .get_storage_map_details_for_keys(account_id, slot_name.clone(), block_num, keys)
            .ok_or_else(|| DatabaseError::StorageRootNotFound {
                account_id,
                slot_name: slot_name.to_string(),
                block_num,
            })?
            .map_err(DatabaseError::MerkleError)?;
        storage_map_details_by_index[index] = Some(details);
    }

    // Handle slots with "all entries" requests
    for (index, slot_name) in all_entries_requests {
        let details =
            match get_storage_map_details_from_forest(view, account_id, &slot_name, block_num)? {
                Some(details) => details,
                None => {
                    reconstruct_storage_map_details_from_db(view, account_id, slot_name, block_num)?
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
            block_num,
        })?;
        storage_map_details.push(details);
    }

    // In case of an "all storage maps" request we have to be careful: even with the per-slot limit
    // of [`AccountStorageMapDetails::MAX_RETURN_ENTRIES`] we might go over the response size limit.
    // Here we make sure that we're within that limit by potentially truncating the response.
    if should_apply_response_budget {
        return Ok(apply_all_storage_maps_response_budget(
            block_num,
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
    block_num: BlockNumber,
    requests: &[StorageMapRequest],
    storage_header: &AccountStorageHeader,
) -> Result<(), GetAccountError> {
    for StorageMapRequest { slot_name, .. } in requests {
        let slot = storage_header.find_slot_header_by_name(slot_name).ok_or_else(|| {
            GetAccountError::StorageSlotNotFound {
                account_id,
                slot_name: slot_name.clone(),
                block_num,
            }
        })?;
        if slot.slot_type() != StorageSlotType::Map {
            return Err(GetAccountError::StorageSlotNotMap {
                account_id,
                slot_name: slot_name.clone(),
                block_num,
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

#[cfg(test)]
mod tests {
    use miden_node_store::GenesisState;
    use miden_node_store::state::State;
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
                AuthScheme::Falcon512Eidos,
            )))
            .build_existing()
            .unwrap()
    }

    async fn bootstrap_store(path: &std::path::Path, account: Account) {
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

        State::bootstrap(genesis_block, path).await.expect("store should bootstrap");
    }

    fn storage_request(account_id: AccountId, request: StorageMapRequest) -> GetAccountRequest {
        GetAccountRequest {
            account_id,
            block_num: None,
            details: Some(AccountDetailRequest {
                code_commitment: None,
                vault_request: AccountVaultRequest::None,
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
        bootstrap_store(data_directory.path(), account).await;
        let (state, _block_writer, _proof_writer) = State::for_tests(data_directory.path()).await;

        let missing_slot = StorageSlotName::new("test::missing").unwrap();
        let map_keys = SlotData::MapKeys(vec![StorageMapKey::from_index(1)]);

        for slot_data in [SlotData::All, map_keys.clone()] {
            let request = StorageMapRequest {
                slot_name: missing_slot.clone(),
                slot_data: slot_data.clone(),
            };
            let result = state
                .read(move |view| get_account(&view, storage_request(account_id, request)))
                .await;
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
            let result = state
                .read(move |view| get_account(&view, storage_request(account_id, request)))
                .await;
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
                .read(move |view| get_account(&view, storage_request(account_id, request)))
                .await
                .expect("map slot request should succeed");
            let details = response.details.expect("details should be returned");
            assert_eq!(details.storage_details.map_details.len(), 1);
            assert_eq!(details.storage_details.map_details[0].slot_name, map_slot_name());
        }
    }
}
