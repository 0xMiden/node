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
use miden_node_proto::generated as proto;
use miden_node_proto::prost::Message as _;
use miden_node_proto::prost::encoding::{encoded_len_varint, key_len};
use miden_node_utils::limiter::MAX_RESPONSE_PAYLOAD_BYTES;
use miden_protocol::account::{
    AccountHeader,
    AccountId,
    AccountStorageHeader,
    StorageSlotName,
    StorageSlotType,
};
use miden_protocol::block::BlockNumber;
use miden_protocol::block::account_tree::AccountWitness;
use tracing::instrument;

use super::State;
use crate::COMPONENT;
use crate::account_state_forest::AccountStorageMapResult;
use crate::errors::{DatabaseError, GetAccountError};
use crate::state::Finality;

impl State {
    /// Returns an account witness and optionally account details at a specific block.
    ///
    /// The witness is a Merkle proof of inclusion in the account tree, proving the account's
    /// state commitment. If `details` is requested, the method also returns the account's code,
    /// vault assets, and storage data. Account details are only available for public accounts.
    ///
    /// If `block_num` is provided, returns the state at that historical block; otherwise, returns
    /// the latest state. Note that historical states are only available for recent blocks close
    /// to the chain tip.
    #[instrument(target = COMPONENT, skip_all)]
    pub async fn get_account(
        &self,
        account_request: AccountRequest,
    ) -> Result<AccountResponse, GetAccountError> {
        let AccountRequest { block_num, account_id, details } = account_request;

        if details.is_some() && !account_id.is_public() {
            return Err(GetAccountError::AccountNotPublic(account_id));
        }

        let (block_num, witness) = self.get_account_witness(block_num, account_id).await?;

        let details = if let Some(request) = details {
            Some(
                self.fetch_public_account_details(account_id, block_num, &witness, request)
                    .await?,
            )
        } else {
            None
        };

        Ok(AccountResponse { block_num, witness, details })
    }

    /// Returns an account witness (Merkle proof of inclusion in the account tree).
    ///
    /// If `block_num` is provided, returns the witness at that historical block;
    /// otherwise, returns the witness at the latest block.
    #[instrument(target = COMPONENT, skip_all)]
    async fn get_account_witness(
        &self,
        block_num: Option<BlockNumber>,
        account_id: AccountId,
    ) -> Result<(BlockNumber, AccountWitness), GetAccountError> {
        self.with_inner_read_blocking(|inner_state| {
            // Determine which block to query
            let (block_num, witness) = if let Some(requested_block) = block_num {
                // Historical query: use the account tree with history
                let witness = inner_state
                    .account_tree
                    .open_at(account_id, requested_block)
                    .ok_or_else(|| {
                        let latest_block = inner_state.account_tree.block_number_latest();
                        if requested_block > latest_block {
                            GetAccountError::UnknownBlock(requested_block)
                        } else {
                            GetAccountError::BlockPruned(requested_block)
                        }
                    })?;
                (requested_block, witness)
            } else {
                // Latest query: use the latest state
                let block_num = inner_state.account_tree.block_number_latest();
                let witness = inner_state.account_tree.open_latest(account_id);
                (block_num, witness)
            };

            Ok((block_num, witness))
        })
    }

    /// Returns storage map details from the forest for a specific account and storage slot.
    ///
    /// The forest can only be used if all hashed keys in the storage map are known in the
    /// reverse-key LRU cache. If any hashed key is unknown, the method returns `Ok(None)` to signal
    /// that the caller should fall back to reconstructing the storage map details from the
    /// database.
    #[instrument(target = COMPONENT, skip_all)]
    fn get_storage_map_details_from_forest(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
        block_num: BlockNumber,
    ) -> Result<Option<AccountStorageMapDetails>, DatabaseError> {
        self.with_forest_read_blocking(|forest| {
            match forest
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
        })
    }

    /// Returns storage map details by reconstructing the storage map from the database.
    async fn reconstruct_storage_map_details_from_db(
        &self,
        account_id: AccountId,
        slot_name: StorageSlotName,
        block_num: BlockNumber,
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
            self.forest
                .write()
                .await
                .cache_storage_map_keys(entries.iter().map(|(raw_key, _)| *raw_key));
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
    #[expect(clippy::too_many_lines)]
    #[instrument(target = COMPONENT, skip_all)]
    async fn fetch_public_account_details(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
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

        // Validate block exists in the blockchain before querying the database
        if block_num > self.chain_tip(Finality::Committed) {
            return Err(GetAccountError::UnknownBlock(block_num));
        }

        // Query account header and storage header together in a single DB call
        let (account_header, storage_header) = self
            .db
            .select_account_header_with_storage_header_at_block(account_id, block_num)
            .await?
            .ok_or(GetAccountError::AccountNotFound(account_id, block_num))?;

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

        // Query account state forest for vault details on commitment mismatch
        let vault_details = match asset_vault_commitment {
            Some(commitment) if commitment == account_header.vault_root() => {
                AccountVaultDetails::empty()
            },
            Some(_) => self.with_forest_read_blocking(|forest| {
                forest.get_vault_details(account_id, block_num).map_err(|err| {
                    DatabaseError::DataCorrupted(format!(
                        "failed to reconstruct vault for account {account_id} at block {block_num}: {err}"
                    ))
                })
            })?,
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
                            block_num,
                            &keys,
                        )
                        .ok_or_else(|| DatabaseError::StorageRootNotFound {
                            account_id,
                            slot_name: slot_name.to_string(),
                            block_num,
                        })?
                        .map_err(DatabaseError::MerkleError)?;
                    storage_map_details_by_index[index] = Some(details);
                }
                Ok::<(), DatabaseError>(())
            })?;
        }

        // Handle slots with "all entries" requests
        for (index, slot_name) in all_entries_requests {
            let details = match self
                .get_storage_map_details_from_forest(account_id, &slot_name, block_num)?
            {
                Some(details) => details,
                None => {
                    self.reconstruct_storage_map_details_from_db(account_id, slot_name, block_num)
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
                block_num,
            })?;
            storage_map_details.push(details);
        }

        // In case of an "all storage maps" request we have to be careful: even with the per-slot
        // limit of [`AccountStorageMapDetails::MAX_RETURN_ENTRIES`] we might go over the response
        // size limit. Here we make sure that we're within that limit by potentially truncating the
        // response.
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

// This is intentionally conservative. Storage slot names can be up to u8::MAX bytes, and a
// `limit_exceeded` map detail stores only the slot name plus the `too_many_entries` flag.
const STORAGE_MAP_LIMIT_EXCEEDED_FIELD_MAX_LEN: usize = 263;

// A conservative limit that makes sure that limit exceeded messages can be appended for all slots
// in the response.
const MAX_ALL_STORAGE_MAPS_RESPONSE_PAYLOAD_WITH_BUDGET_RESERVED_FOR_LIMIT_EXCEEDED_SLOTS: usize =
    MAX_RESPONSE_PAYLOAD_BYTES - 256 * STORAGE_MAP_LIMIT_EXCEEDED_FIELD_MAX_LEN - 8192;

// Conservative max length for storage map entries: key-value pairs, each one is four `fixed64`
// values plus Protobuf overhead.
const STORAGE_MAP_ENTRY_MAX_LEN: usize = 78;

fn protobuf_bytes_field_len(field_number: u32, len: usize) -> usize {
    key_len(field_number) + encoded_len_varint(len as u64) + len
}

/// Give an upper estimate for the encoded size of a single storage map.
fn estimate_storage_map_details_field_len(details: &AccountStorageMapDetails) -> usize {
    match &details.entries {
        StorageMapEntries::LimitExceeded => STORAGE_MAP_LIMIT_EXCEEDED_FIELD_MAX_LEN,
        StorageMapEntries::AllEntries(entries) => {
            let slot_name_len = details.slot_name.as_str().len();
            let slot_name_field_len = protobuf_bytes_field_len(1, slot_name_len);
            let all_entries_payload_len = entries.len() * STORAGE_MAP_ENTRY_MAX_LEN;
            let all_entries_field_len = protobuf_bytes_field_len(3, all_entries_payload_len);
            let details_len = slot_name_field_len + all_entries_field_len;

            protobuf_bytes_field_len(2, details_len)
        },
        // `apply_all_storage_maps_response_budget()` is only used for `all_storage_maps` requests,
        // which never request proofs. Be conservative and force the fallback path if this changes.
        StorageMapEntries::EntriesWithProofs(_) => usize::MAX,
    }
}

/// Limit response size to a payload budget.
///
/// Ensures that the [`AccountDetails`] response fits into `max_response_payload_bytes` when encoded.
/// We iterate over the individual storage map slots and:
/// - keep the map contents is we're still within our response size budget
/// - replace the contents with "limit exceeded" if we're past the response size budget.
///
/// We reserve space for the "limit exceeded" responses in advance so we're safe to start appending
/// "limit exceeded" at any point during iteration.
#[expect(clippy::too_many_arguments)]
fn apply_all_storage_maps_response_budget(
    block_num: BlockNumber,
    witness: &AccountWitness,
    account_header: AccountHeader,
    account_code: Option<Vec<u8>>,
    vault_details: AccountVaultDetails,
    storage_header: AccountStorageHeader,
    ordered_map_details: Vec<AccountStorageMapDetails>,
    ordered_map_slot_names: Vec<StorageSlotName>,
    max_response_payload_bytes: usize,
) -> AccountDetails {
    let mut accepted_map_details = Vec::with_capacity(ordered_map_details.len());
    let base_response_size_without_map_details =
        proto::rpc::AccountResponse::from(AccountResponse {
            block_num,
            witness: witness.clone(),
            details: Some(AccountDetails {
                account_header: account_header.clone(),
                account_code: account_code.clone(),
                vault_details: vault_details.clone(),
                storage_details: AccountStorageDetails {
                    header: storage_header.clone(),
                    map_details: vec![],
                },
            }),
        })
        .encoded_len();
    let available_map_details_budget =
        max_response_payload_bytes.saturating_sub(base_response_size_without_map_details);
    let reserved_limit_exceeded_budget =
        ordered_map_slot_names.len() * STORAGE_MAP_LIMIT_EXCEEDED_FIELD_MAX_LEN;
    let mut extra_budget_for_full_maps =
        available_map_details_budget.saturating_sub(reserved_limit_exceeded_budget);

    for (details, slot_name) in ordered_map_details.into_iter().zip(ordered_map_slot_names) {
        let estimated_details_len = estimate_storage_map_details_field_len(&details);
        let extra_cost_over_limit_exceeded =
            estimated_details_len.saturating_sub(STORAGE_MAP_LIMIT_EXCEEDED_FIELD_MAX_LEN);

        if extra_cost_over_limit_exceeded <= extra_budget_for_full_maps {
            extra_budget_for_full_maps -= extra_cost_over_limit_exceeded;
            accepted_map_details.push(details);
        } else {
            accepted_map_details.push(AccountStorageMapDetails::limit_exceeded(slot_name));
        }
    }

    AccountDetails {
        account_header,
        account_code,
        vault_details,
        storage_details: AccountStorageDetails {
            header: storage_header,
            map_details: accepted_map_details,
        },
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_node_proto::domain::account::{
        AccountDetails,
        AccountResponse,
        AccountStorageDetails,
        AccountStorageMapDetails,
        AccountStorageRequest,
        AccountVaultDetails,
        SlotData,
        StorageMapEntries,
        StorageMapRequest,
    };
    use miden_protocol::account::{
        AccountHeader,
        AccountId,
        AccountStorageHeader,
        StorageMapKey,
        StorageSlotHeader,
        StorageSlotName,
        StorageSlotType,
    };
    use miden_protocol::block::BlockNumber;
    use miden_protocol::block::account_tree::{AccountIdKey, AccountTree, AccountWitness};
    use miden_protocol::crypto::merkle::smt::{LargeSmt, MemoryStorage};
    use miden_protocol::testing::account_id::AccountIdBuilder;
    use miden_protocol::{EMPTY_WORD, Felt, Word};

    use super::{apply_all_storage_maps_response_budget, expand_account_storage_request};

    fn storage_header() -> AccountStorageHeader {
        AccountStorageHeader::new(vec![
            StorageSlotHeader::new(StorageSlotName::mock(0), StorageSlotType::Value, EMPTY_WORD),
            StorageSlotHeader::new(StorageSlotName::mock(1), StorageSlotType::Map, EMPTY_WORD),
            StorageSlotHeader::new(StorageSlotName::mock(2), StorageSlotType::Map, EMPTY_WORD),
        ])
        .unwrap()
    }

    fn account_id() -> AccountId {
        AccountIdBuilder::new().build_with_seed([42; 32])
    }

    fn account_header(account_id: AccountId) -> AccountHeader {
        AccountHeader::new(account_id, Felt::ZERO, EMPTY_WORD, EMPTY_WORD, EMPTY_WORD)
    }

    fn account_witness(account_id: AccountId) -> AccountWitness {
        let smt = LargeSmt::with_entries(
            MemoryStorage::default(),
            [(AccountIdKey::from(account_id).as_word(), EMPTY_WORD)],
        )
        .unwrap();
        AccountTree::new(smt).unwrap().open(account_id)
    }

    fn map_details(slot_name: StorageSlotName, value: Word) -> AccountStorageMapDetails {
        AccountStorageMapDetails {
            slot_name,
            entries: StorageMapEntries::AllEntries(vec![(StorageMapKey::from_index(1), value)]),
        }
    }

    fn map_details_with_entries(
        slot_name: StorageSlotName,
        entry_count: u8,
    ) -> AccountStorageMapDetails {
        AccountStorageMapDetails {
            slot_name,
            entries: StorageMapEntries::AllEntries(
                (1..=entry_count)
                    .map(|index| {
                        (
                            StorageMapKey::from_index(u32::from(index)),
                            Word::from([u32::from(index), 0, 0, 0]),
                        )
                    })
                    .collect(),
            ),
        }
    }

    #[test]
    fn all_storage_maps_expands_only_map_slots() {
        let requests = expand_account_storage_request(
            AccountStorageRequest::AllStorageMaps,
            &storage_header(),
        );

        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].slot_name, StorageSlotName::mock(1));
        assert_eq!(requests[1].slot_name, StorageSlotName::mock(2));
        assert!(requests.iter().all(|request| request.slot_data == SlotData::All));
    }

    #[test]
    fn explicit_storage_maps_are_preserved() {
        let slot_name = StorageSlotName::mock(2);
        let explicit = vec![StorageMapRequest {
            slot_name: slot_name.clone(),
            slot_data: SlotData::All,
        }];

        let requests = expand_account_storage_request(
            AccountStorageRequest::Explicit(explicit.clone()),
            &storage_header(),
        );

        assert_eq!(requests, explicit);
        assert_eq!(requests[0].slot_name, slot_name);
    }

    #[test]
    fn absent_storage_slot_data_expands_to_no_requests() {
        let requests =
            expand_account_storage_request(AccountStorageRequest::None, &storage_header());

        assert!(requests.is_empty());
    }

    #[test]
    fn limit_exceeded_max_size_covers_max_slot_name() {
        use miden_node_proto::prost::Message;

        let max_slot_name = StorageSlotName::new(format!("a::{}", "a".repeat(252))).unwrap();

        let details = super::proto::rpc::account_storage_details::AccountStorageMapDetails::from(
            AccountStorageMapDetails::limit_exceeded(max_slot_name),
        );

        assert!(super::STORAGE_MAP_LIMIT_EXCEEDED_FIELD_MAX_LEN >= details.encoded_len());
    }

    #[test]
    fn all_entries_size_estimate_covers_actual_protobuf_size() {
        use miden_node_proto::prost::Message;

        let details = map_details(StorageSlotName::mock(1), Word::from([1u32, 0, 0, 0]));
        let actual = super::proto::rpc::account_storage_details::AccountStorageMapDetails::from(
            details.clone(),
        )
        .encoded_len();

        assert!(super::estimate_storage_map_details_field_len(&details) >= actual);
    }

    #[test]
    fn all_storage_maps_budget_marks_maps_as_limit_exceeded_when_budget_is_exhausted() {
        use miden_node_proto::prost::Message;

        let account_id = account_id();
        let witness = account_witness(account_id);
        let header = account_header(account_id);
        let storage_header = storage_header();
        let slot_1 = StorageSlotName::mock(1);
        let slot_2 = StorageSlotName::mock(2);
        let marker_only_budget = super::proto::rpc::AccountResponse::from(AccountResponse {
            block_num: BlockNumber::GENESIS,
            witness: witness.clone(),
            details: Some(AccountDetails {
                account_header: header.clone(),
                account_code: None,
                vault_details: AccountVaultDetails::empty(),
                storage_details: AccountStorageDetails {
                    header: storage_header.clone(),
                    map_details: vec![
                        AccountStorageMapDetails::limit_exceeded(slot_1.clone()),
                        AccountStorageMapDetails::limit_exceeded(slot_2.clone()),
                    ],
                },
            }),
        })
        .encoded_len();
        let details = apply_all_storage_maps_response_budget(
            BlockNumber::GENESIS,
            &witness,
            header,
            None,
            AccountVaultDetails::empty(),
            storage_header,
            vec![
                map_details_with_entries(slot_1.clone(), 8),
                map_details_with_entries(slot_2.clone(), 8),
            ],
            vec![slot_1.clone(), slot_2.clone()],
            marker_only_budget,
        );

        assert_eq!(details.storage_details.map_details.len(), 2);
        assert_eq!(details.storage_details.map_details[0].slot_name, slot_1);
        assert_eq!(
            details.storage_details.map_details[0].entries,
            StorageMapEntries::LimitExceeded
        );
        assert_eq!(details.storage_details.map_details[1].slot_name, slot_2);
        assert_eq!(
            details.storage_details.map_details[1].entries,
            StorageMapEntries::LimitExceeded
        );
    }

    #[test]
    fn all_storage_maps_budget_stays_under_hard_cap_with_many_limit_exceeded_maps() {
        use miden_node_proto::prost::Message;

        let account_id = account_id();
        let witness = account_witness(account_id);
        let header = account_header(account_id);
        let mut slot_names: Vec<_> = (1..10).map(StorageSlotName::mock).collect();
        slot_names.sort();
        let storage_header = AccountStorageHeader::new(
            slot_names
                .iter()
                .cloned()
                .map(|slot_name| {
                    StorageSlotHeader::new(slot_name, StorageSlotType::Map, EMPTY_WORD)
                })
                .collect(),
        )
        .unwrap();
        let marker_only_hard_cap = super::proto::rpc::AccountResponse::from(AccountResponse {
            block_num: BlockNumber::GENESIS,
            witness: witness.clone(),
            details: Some(AccountDetails {
                account_header: header.clone(),
                account_code: None,
                vault_details: AccountVaultDetails::empty(),
                storage_details: AccountStorageDetails {
                    header: storage_header.clone(),
                    map_details: slot_names
                        .iter()
                        .cloned()
                        .map(AccountStorageMapDetails::limit_exceeded)
                        .collect(),
                },
            }),
        })
        .encoded_len();

        let details = apply_all_storage_maps_response_budget(
            BlockNumber::GENESIS,
            &witness,
            header,
            None,
            AccountVaultDetails::empty(),
            storage_header,
            slot_names
                .iter()
                .cloned()
                .map(|slot_name| map_details_with_entries(slot_name, 8))
                .collect(),
            slot_names.clone(),
            marker_only_hard_cap,
        );

        assert_eq!(details.storage_details.map_details.len(), slot_names.len());
        assert!(
            details
                .storage_details
                .map_details
                .iter()
                .all(|details| details.entries == StorageMapEntries::LimitExceeded)
        );
        assert!(
            super::proto::rpc::AccountResponse::from(AccountResponse {
                block_num: BlockNumber::GENESIS,
                witness,
                details: Some(details),
            })
            .encoded_len()
                <= marker_only_hard_cap
        );
    }

    #[test]
    fn all_storage_maps_budget_keeps_entries_that_fit() {
        let account_id = account_id();
        let slot_1 = StorageSlotName::mock(1);
        let details = apply_all_storage_maps_response_budget(
            BlockNumber::GENESIS,
            &account_witness(account_id),
            account_header(account_id),
            None,
            AccountVaultDetails::empty(),
            storage_header(),
            vec![map_details(slot_1.clone(), Word::from([1u32, 0, 0, 0]))],
            vec![slot_1.clone()],
            usize::MAX,
        );

        assert_eq!(details.storage_details.map_details.len(), 1);
        assert_eq!(details.storage_details.map_details[0].slot_name, slot_1);
        assert!(matches!(
            details.storage_details.map_details[0].entries,
            StorageMapEntries::AllEntries(_)
        ));
    }
}
