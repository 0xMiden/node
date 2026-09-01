use miden_node_utils::limiter::{QueryParamLimiter, QueryParamStorageMapKeyTotalLimit};
use miden_protocol::Word;
#[cfg(test)]
use miden_protocol::account::StorageSlotHeader;
use miden_protocol::account::{
    Account,
    AccountCode,
    AccountHeader,
    AccountId,
    AccountStorageHeader,
    StorageMap,
    StorageMapKey,
    StorageSlotName,
    StorageSlotType,
};
use miden_protocol::asset::Asset;
use miden_protocol::block::BlockNumber;
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::crypto::merkle::MerkleError;
use miden_protocol::crypto::merkle::smt::{PartialSmt, SmtProof};
use miden_protocol::utils::serde::{Deserializable, Serializable};

use super::try_convert;
use crate::decode;
use crate::decode::{ConversionResultExt, GrpcDecodeExt};
use crate::errors::ConversionError;
use crate::generated::{self as proto};

#[cfg(test)]
mod tests;

// ACCOUNT UPDATE
// ================================================================================================

#[derive(Debug, PartialEq)]
pub struct AccountSummary {
    pub account_id: AccountId,
    pub account_commitment: Word,
    pub block_num: BlockNumber,
}

#[derive(Debug, PartialEq)]
pub struct AccountInfo {
    pub summary: AccountSummary,
    pub details: Option<Account>,
}

// ACCOUNT REQUEST
// ================================================================================================

/// Represents a request for an account proof.
#[derive(Debug)]
pub struct AccountRequest {
    pub account_id: AccountId,
    // If not present, the latest account proof references the latest available
    pub block_num: Option<BlockNumber>,
    pub details: Option<AccountDetailRequest>,
}

impl TryFrom<proto::rpc::AccountRequest> for AccountRequest {
    type Error = ConversionError;

    fn try_from(value: proto::rpc::AccountRequest) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let proto::rpc::AccountRequest { account_id, block_num, details } = value;

        let account_id = decode!(decoder, account_id)?;
        let block_num = block_num.map(Into::into);

        let details = details.map(TryFrom::try_from).transpose().context("details")?;

        Ok(AccountRequest { account_id, block_num, details })
    }
}

/// Represents a request for account details alongside specific storage data.
#[derive(Debug)]
pub struct AccountDetailRequest {
    pub code_commitment: Option<Word>,
    pub asset_vault_commitment: Option<Word>,
    pub storage_request: AccountStorageRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountStorageRequest {
    None,
    AllStorageMaps,
    Explicit(Vec<StorageMapRequest>),
}

impl TryFrom<proto::rpc::account_request::AccountDetailRequest> for AccountDetailRequest {
    type Error = ConversionError;

    fn try_from(
        value: proto::rpc::account_request::AccountDetailRequest,
    ) -> Result<Self, Self::Error> {
        use proto::rpc::account_request::account_detail_request::StorageRequest as ProtoStorageRequest;

        let proto::rpc::account_request::AccountDetailRequest {
            code_commitment,
            asset_vault_commitment,
            storage_request,
        } = value;

        let code_commitment =
            code_commitment.map(TryFrom::try_from).transpose().context("code_commitment")?;
        let asset_vault_commitment = asset_vault_commitment
            .map(TryFrom::try_from)
            .transpose()
            .context("asset_vault_commitment")?;

        let storage_request = match storage_request {
            None => AccountStorageRequest::None,
            Some(ProtoStorageRequest::AllStorageMaps(true)) => {
                AccountStorageRequest::AllStorageMaps
            },
            Some(ProtoStorageRequest::AllStorageMaps(false)) => {
                return Err(ConversionError::message("all_storage_maps must be true when set"));
            },
            Some(ProtoStorageRequest::StorageMaps(requests)) => {
                let requests = try_convert(requests.storage_maps)
                    .collect::<Result<_, _>>()
                    .context("storage_maps")?;
                AccountStorageRequest::Explicit(requests)
            },
        };

        Ok(AccountDetailRequest {
            code_commitment,
            asset_vault_commitment,
            storage_request,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageMapRequest {
    pub slot_name: StorageSlotName,
    pub slot_data: SlotData,
}

impl TryFrom<proto::rpc::account_request::account_detail_request::StorageMapDetailRequest>
    for StorageMapRequest
{
    type Error = ConversionError;

    fn try_from(
        value: proto::rpc::account_request::account_detail_request::StorageMapDetailRequest,
    ) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let proto::rpc::account_request::account_detail_request::StorageMapDetailRequest {
            slot_name,
            slot_data,
        } = value;

        let slot_name = StorageSlotName::new(slot_name).context("slot_name")?;
        let slot_data = decode!(decoder, slot_data)?;

        Ok(StorageMapRequest { slot_name, slot_data })
    }
}

/// Request of slot data values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotData {
    All,
    MapKeys(Vec<StorageMapKey>),
}

impl
    TryFrom<
        proto::rpc::account_request::account_detail_request::storage_map_detail_request::SlotData,
    > for SlotData
{
    type Error = ConversionError;

    fn try_from(
        value: proto::rpc::account_request::account_detail_request::storage_map_detail_request::SlotData,
    ) -> Result<Self, Self::Error> {
        use proto::rpc::account_request::account_detail_request::storage_map_detail_request::SlotData as ProtoSlotData;

        Ok(match value {
            ProtoSlotData::AllEntries(true) => SlotData::All,
            ProtoSlotData::AllEntries(false) => {
                return Err(ConversionError::message("enum variant discriminant out of range"));
            },
            ProtoSlotData::MapKeys(keys) => {
                let keys = keys
                    .map_keys
                    .into_iter()
                    .map(|key| {
                        Word::try_from(key).map(StorageMapKey::new).map_err(ConversionError::from)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if has_duplicate_storage_map_keys(&keys) {
                    return Err(ConversionError::message(
                        "storage map key request contains duplicate keys",
                    ));
                }
                SlotData::MapKeys(keys)
            },
        })
    }
}

fn has_duplicate_storage_map_keys(keys: &[StorageMapKey]) -> bool {
    keys.iter().enumerate().any(|(index, key)| keys[..index].contains(key))
}

// ACCOUNT VAULT DETAILS
//================================================================================================

/// Account vault details
///
/// When an account contains a large number of assets (>
/// [`AccountVaultDetails::MAX_RETURN_ENTRIES`]), including all assets in a single RPC response
/// creates performance issues. In such cases, the `LimitExceeded` variant indicates to the client
/// to use the `SyncAccountVault` endpoint instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountVaultDetails {
    /// The vault has too many assets to return inline. Clients must use `SyncAccountVault` endpoint
    /// instead.
    LimitExceeded,

    /// The assets in the vault (up to `MAX_RETURN_ENTRIES`).
    Assets(Vec<Asset>),
}

impl AccountVaultDetails {
    /// Maximum number of vault entries that can be returned in a single response. Accounts with
    /// more assets will have `LimitExceeded` variant.
    pub const MAX_RETURN_ENTRIES: usize = 1000;

    pub fn empty() -> Self {
        Self::Assets(Vec::new())
    }

    /// Creates `AccountVaultDetails` from a list of assets.
    pub fn from_assets(assets: Vec<Asset>) -> Self {
        if assets.len() > Self::MAX_RETURN_ENTRIES {
            Self::LimitExceeded
        } else {
            Self::Assets(assets)
        }
    }
}

impl TryFrom<proto::rpc::AccountVaultDetails> for AccountVaultDetails {
    type Error = ConversionError;

    fn try_from(value: proto::rpc::AccountVaultDetails) -> Result<Self, Self::Error> {
        let proto::rpc::AccountVaultDetails { too_many_assets, assets } = value;

        if too_many_assets {
            Ok(Self::LimitExceeded)
        } else {
            let parsed_assets = assets
                .into_iter()
                .map(|asset| Asset::try_from(asset).map_err(ConversionError::from))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Self::Assets(parsed_assets))
        }
    }
}

impl From<AccountVaultDetails> for proto::rpc::AccountVaultDetails {
    fn from(value: AccountVaultDetails) -> Self {
        match value {
            AccountVaultDetails::LimitExceeded => Self {
                too_many_assets: true,
                assets: Vec::new(),
            },
            AccountVaultDetails::Assets(assets) => Self {
                too_many_assets: false,
                assets: Vec::from_iter(assets.into_iter().map(proto::primitives::Asset::from)),
            },
        }
    }
}

// ACCOUNT STORAGE MAP DETAILS
//================================================================================================

/// Details about an account storage map slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountStorageMapDetails {
    pub slot_name: StorageSlotName,
    pub entries: StorageMapEntries,
}

/// Storage map entries for an account storage slot.
///
/// When a storage map contains many entries (> [`AccountStorageMapDetails::MAX_RETURN_ENTRIES`]),
/// returning all entries in a single RPC response creates performance issues. In such cases,
/// the `LimitExceeded` variant indicates to the client to use the `SyncAccountStorageMaps` endpoint
/// instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageMapEntries {
    /// The map has too many entries to return inline. Clients must use `SyncAccountStorageMaps`
    /// endpoint instead.
    LimitExceeded,

    /// All storage map entries (key-value pairs) without proofs. Used when all entries are
    /// requested for small maps.
    AllEntries(Vec<(StorageMapKey, Word)>),

    /// Specific raw map keys covered by a single partial SMT. Used when specific keys are requested
    /// from the storage map.
    PartialMap {
        map_keys: Vec<StorageMapKey>,
        partial_smt: PartialSmt,
    },
}

impl AccountStorageMapDetails {
    /// Maximum number of storage map entries that can be returned in a single response.
    pub const MAX_RETURN_ENTRIES: usize = 1000;

    /// Maximum number of SMT proofs that can be returned in a single response.
    ///
    /// This limit is more restrictive than [`Self::MAX_RETURN_ENTRIES`] because SMT proofs
    /// are larger (up to 64 inner nodes each) and more CPU-intensive to generate.
    ///
    /// This is defined by [`QueryParamStorageMapKeyTotalLimit::LIMIT`] and used both in RPC
    /// validation and store-level enforcement to ensure consistent limits.
    pub const MAX_SMT_PROOF_ENTRIES: usize = QueryParamStorageMapKeyTotalLimit::LIMIT;

    /// Creates storage map details with all entries from the storage map.
    ///
    /// If the storage map has too many entries (> `MAX_RETURN_ENTRIES`),
    /// returns `LimitExceeded` variant.
    pub fn from_all_entries(slot_name: StorageSlotName, storage_map: &StorageMap) -> Self {
        if storage_map.num_entries() > Self::MAX_RETURN_ENTRIES {
            Self {
                slot_name,
                entries: StorageMapEntries::LimitExceeded,
            }
        } else {
            let entries = Vec::from_iter(storage_map.entries().map(|(k, v)| (*k, *v)));
            Self {
                slot_name,
                entries: StorageMapEntries::AllEntries(entries),
            }
        }
    }

    /// Creates storage map details from forest-queried entries.
    ///
    /// Returns `LimitExceeded` if too many entries.
    pub fn from_forest_entries(
        slot_name: StorageSlotName,
        entries: Vec<(StorageMapKey, Word)>,
    ) -> Self {
        if entries.len() > Self::MAX_RETURN_ENTRIES {
            Self {
                slot_name,
                entries: StorageMapEntries::LimitExceeded,
            }
        } else {
            Self {
                slot_name,
                entries: StorageMapEntries::AllEntries(entries),
            }
        }
    }

    /// Creates storage map details from pre-computed SMT proofs.
    ///
    /// Use this when the caller has already obtained the proofs from an `SmtForest`.
    /// Returns `LimitExceeded` if too many proofs are provided.
    pub fn from_proofs(
        slot_name: StorageSlotName,
        map_root: Word,
        map_keys: Vec<StorageMapKey>,
        proofs: Vec<SmtProof>,
    ) -> Result<Self, MerkleError> {
        if map_keys.len() != proofs.len() {
            return Err(MerkleError::InternalError(format!(
                "storage map key count {} does not match proof count {}",
                map_keys.len(),
                proofs.len()
            )));
        }
        if has_duplicate_storage_map_keys(&map_keys) {
            return Err(MerkleError::InternalError(
                "storage map key list contains duplicate keys".into(),
            ));
        }

        if map_keys.len() > Self::MAX_SMT_PROOF_ENTRIES {
            return Ok(Self {
                slot_name,
                entries: StorageMapEntries::LimitExceeded,
            });
        }

        let partial_smt = if proofs.is_empty() {
            PartialSmt::new(map_root)
        } else {
            PartialSmt::from_proofs(proofs)?
        };

        if partial_smt.root() != map_root {
            return Err(MerkleError::ConflictingRoots {
                expected_root: map_root,
                actual_root: partial_smt.root(),
            });
        }

        for map_key in &map_keys {
            partial_smt.get_value(&map_key.hash().as_word())?;
        }

        Ok(Self {
            slot_name,
            entries: StorageMapEntries::PartialMap { map_keys, partial_smt },
        })
    }

    /// Creates storage map details indicating the limit was exceeded.
    pub fn limit_exceeded(slot_name: StorageSlotName) -> Self {
        Self {
            slot_name,
            entries: StorageMapEntries::LimitExceeded,
        }
    }
}

impl TryFrom<proto::rpc::account_storage_details::AccountStorageMapDetails>
    for AccountStorageMapDetails
{
    type Error = ConversionError;

    fn try_from(
        value: proto::rpc::account_storage_details::AccountStorageMapDetails,
    ) -> Result<Self, Self::Error> {
        use proto::rpc::account_storage_details::account_storage_map_details::{
            AllMapEntries,
            PartialStorageMap,
            Result as ProtoResult,
        };

        let decoder = value.decoder();
        let proto::rpc::account_storage_details::AccountStorageMapDetails { slot_name, result } =
            value;

        let slot_name = StorageSlotName::new(slot_name).context("slot_name")?;

        let entries = match decode!(decoder, result)? {
            ProtoResult::TooManyEntries(true) => StorageMapEntries::LimitExceeded,
            ProtoResult::TooManyEntries(false) => {
                return Err(ConversionError::message("too_many_entries must be true when set"));
            },
            ProtoResult::AllEntries(AllMapEntries { entries }) => {
                let entries = entries
                    .into_iter()
                    .map(|entry| {
                        let decoder = entry.decoder();
                        let key = StorageMapKey::new(decode!(decoder, entry.key)?);
                        let value = decode!(decoder, entry.value)?;
                        Ok((key, value))
                    })
                    .collect::<Result<Vec<_>, ConversionError>>()
                    .context("entries")?;
                StorageMapEntries::AllEntries(entries)
            },
            ProtoResult::PartialMap(PartialStorageMap { map_keys, partial_smt }) => {
                if map_keys.len() > Self::MAX_SMT_PROOF_ENTRIES {
                    return Err(ConversionError::message(format!(
                        "partial storage map contains {} keys, exceeding the limit of {}",
                        map_keys.len(),
                        Self::MAX_SMT_PROOF_ENTRIES
                    )));
                }
                let map_keys = map_keys
                    .into_iter()
                    .map(|key| Word::try_from(key).map(StorageMapKey::new))
                    .collect::<Result<Vec<_>, _>>()
                    .context("map_keys")?;
                if has_duplicate_storage_map_keys(&map_keys) {
                    return Err(ConversionError::message(
                        "partial storage map contains duplicate keys",
                    ));
                }
                let partial_smt: PartialSmt =
                    decode!(decoder, partial_smt).context("partial_smt")?;
                for map_key in &map_keys {
                    partial_smt.get_value(&map_key.hash().as_word()).context("map_keys")?;
                }
                StorageMapEntries::PartialMap { map_keys, partial_smt }
            },
        };

        Ok(Self { slot_name, entries })
    }
}

impl From<AccountStorageMapDetails>
    for proto::rpc::account_storage_details::AccountStorageMapDetails
{
    fn from(value: AccountStorageMapDetails) -> Self {
        use proto::rpc::account_storage_details::account_storage_map_details::{
            AllMapEntries,
            PartialStorageMap,
            Result as ProtoResult,
        };

        let AccountStorageMapDetails { slot_name, entries } = value;

        let result = match entries {
            StorageMapEntries::LimitExceeded => ProtoResult::TooManyEntries(true),
            StorageMapEntries::AllEntries(entries) => {
                let all = AllMapEntries {
                    entries: Vec::from_iter(entries.into_iter().map(|(key, value)| {
                        proto::rpc::account_storage_details::account_storage_map_details::all_map_entries::StorageMapEntry {
                            key: Some(Word::from(key).into()),
                            value: Some(value.into()),
                        }
                    })),
                };
                ProtoResult::AllEntries(all)
            },
            StorageMapEntries::PartialMap { map_keys, partial_smt } => {
                ProtoResult::PartialMap(PartialStorageMap {
                    map_keys: map_keys
                        .into_iter()
                        .map(|key| proto::primitives::Word::from(Word::from(key)))
                        .collect(),
                    partial_smt: Some(partial_smt.into()),
                })
            },
        };

        Self {
            slot_name: slot_name.to_string(),
            result: Some(result),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AccountStorageDetails {
    pub header: AccountStorageHeader,
    pub map_details: Vec<AccountStorageMapDetails>,
}

impl AccountStorageDetails {
    /// Creates storage details where all map slots indicate limit exceeded.
    pub fn all_limits_exceeded(
        header: AccountStorageHeader,
        slot_names: impl IntoIterator<Item = StorageSlotName>,
    ) -> Self {
        Self {
            header,
            map_details: Vec::from_iter(
                slot_names.into_iter().map(AccountStorageMapDetails::limit_exceeded),
            ),
        }
    }
}

impl TryFrom<proto::rpc::AccountStorageDetails> for AccountStorageDetails {
    type Error = ConversionError;

    fn try_from(value: proto::rpc::AccountStorageDetails) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let proto::rpc::AccountStorageDetails { header, map_details } = value;

        let header: AccountStorageHeader = decode!(decoder, header)?;

        let map_details: Vec<AccountStorageMapDetails> =
            try_convert(map_details).collect::<Result<Vec<_>, _>>().context("map_details")?;

        for map_detail in &map_details {
            let StorageMapEntries::PartialMap { partial_smt, .. } = &map_detail.entries else {
                continue;
            };

            let slot = header.find_slot_header_by_name(&map_detail.slot_name).ok_or_else(|| {
                ConversionError::message(format!(
                    "partial storage map references unknown slot {}",
                    map_detail.slot_name
                ))
            })?;
            if slot.slot_type() != StorageSlotType::Map {
                return Err(ConversionError::message(format!(
                    "partial storage map references non-map slot {}",
                    map_detail.slot_name
                )));
            }
            if partial_smt.root() != slot.value() {
                return Err(ConversionError::message(format!(
                    "partial storage map root for slot {} does not match storage header",
                    map_detail.slot_name
                )));
            }
        }

        Ok(Self { header, map_details })
    }
}

impl From<AccountStorageDetails> for proto::rpc::AccountStorageDetails {
    fn from(value: AccountStorageDetails) -> Self {
        let AccountStorageDetails { header, map_details } = value;

        Self {
            header: Some(header.into()),
            map_details: map_details.into_iter().map(Into::into).collect(),
        }
    }
}

// ACCOUNT PROOF RESPONSE
//================================================================================================

/// Represents the response to an account proof request.
pub struct AccountResponse {
    pub block_num: BlockNumber,
    pub witness: AccountWitness,
    pub details: Option<AccountDetails>,
}

impl TryFrom<proto::rpc::AccountResponse> for AccountResponse {
    type Error = ConversionError;

    fn try_from(value: proto::rpc::AccountResponse) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let proto::rpc::AccountResponse { block_num, witness, details } = value;

        let block_num = decode!(decoder, block_num)?;

        let witness = decode!(decoder, witness)?;

        let details = details.map(TryFrom::try_from).transpose().context("details")?;

        Ok(AccountResponse { block_num, witness, details })
    }
}

impl From<AccountResponse> for proto::rpc::AccountResponse {
    fn from(value: AccountResponse) -> Self {
        let AccountResponse { block_num, witness, details } = value;

        Self {
            witness: Some(witness.into()),
            details: details.map(Into::into),
            block_num: Some(block_num.into()),
        }
    }
}

// ACCOUNT DETAILS
//================================================================================================

/// Represents account details returned in response to an account proof request.
pub struct AccountDetails {
    pub account_header: AccountHeader,
    pub account_code: Option<Vec<u8>>,
    pub vault_details: AccountVaultDetails,
    pub storage_details: AccountStorageDetails,
}

impl AccountDetails {
    /// Creates account details where all storage map slots indicate limit exceeded.
    pub fn with_storage_limits_exceeded(
        account_header: AccountHeader,
        account_code: Option<Vec<u8>>,
        vault_details: AccountVaultDetails,
        storage_header: AccountStorageHeader,
        slot_names: impl IntoIterator<Item = StorageSlotName>,
    ) -> Self {
        Self {
            account_header,
            account_code,
            vault_details,
            storage_details: AccountStorageDetails::all_limits_exceeded(storage_header, slot_names),
        }
    }
}

impl TryFrom<proto::rpc::account_response::AccountDetails> for AccountDetails {
    type Error = ConversionError;

    fn try_from(value: proto::rpc::account_response::AccountDetails) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let proto::rpc::account_response::AccountDetails {
            header,
            code,
            vault_details,
            storage_details,
        } = value;

        let account_header = decode!(decoder, header)?;

        let storage_details = decode!(decoder, storage_details)?;

        let vault_details = decode!(decoder, vault_details)?;
        let account_code = code
            .map(AccountCode::try_from)
            .transpose()
            .map_err(ConversionError::from)?
            .map(|code| code.to_bytes());

        Ok(AccountDetails {
            account_header,
            account_code,
            vault_details,
            storage_details,
        })
    }
}

impl From<AccountDetails> for proto::rpc::account_response::AccountDetails {
    fn from(value: AccountDetails) -> Self {
        let AccountDetails {
            account_header,
            storage_details,
            account_code,
            vault_details,
        } = value;

        let header = Some(proto::account::AccountHeader::from(account_header));
        let storage_details = Some(storage_details.into());
        let code = account_code
            .map(|bytes| {
                AccountCode::read_from_bytes(&bytes)
                    .map_err(ConversionError::from)
                    .map(Into::into)
            })
            .transpose()
            .expect("stored account code bytes must be valid");
        let vault_details = Some(vault_details.into());

        Self {
            header,
            storage_details,
            code,
            vault_details,
        }
    }
}
