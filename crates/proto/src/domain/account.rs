use std::fmt::{Debug, Display, Formatter};

use miden_node_utils::formatting::format_opt;
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamStorageMapKeyTotalLimit};
use miden_protocol::Word;
use miden_protocol::account::{
    Account,
    AccountHeader,
    AccountId,
    AccountStorageHeader,
    StorageMap,
    StorageSlotHeader,
    StorageSlotName,
    StorageSlotType,
};
use miden_protocol::asset::{Asset, AssetVault};
use miden_protocol::block::BlockNumber;
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::crypto::merkle::smt::SmtProof;
use miden_protocol::note::NoteAttachment;
use miden_protocol::utils::{Deserializable, DeserializationError, Serializable};
use miden_standards::note::{NetworkAccountTarget, NetworkAccountTargetError};
use thiserror::Error;

use super::try_convert;
use crate::errors::{ConversionError, MissingFieldHelper};
use crate::generated::{self as proto};

#[cfg(test)]
mod tests;

// ACCOUNT ID
// ================================================================================================

impl Display for proto::account::AccountId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x")?;
        for byte in &self.id {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Debug for proto::account::AccountId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

// FROM PROTO ACCOUNT ID
// ------------------------------------------------------------------------------------------------

impl TryFrom<proto::account::AccountId> for AccountId {
    type Error = ConversionError;

    fn try_from(account_id: proto::account::AccountId) -> Result<Self, Self::Error> {
        AccountId::read_from_bytes(&account_id.id).map_err(|_| ConversionError::NotAValidFelt)
    }
}

// INTO PROTO ACCOUNT ID
// ------------------------------------------------------------------------------------------------

impl From<&AccountId> for proto::account::AccountId {
    fn from(account_id: &AccountId) -> Self {
        (*account_id).into()
    }
}

impl From<AccountId> for proto::account::AccountId {
    fn from(account_id: AccountId) -> Self {
        Self { id: account_id.to_bytes() }
    }
}

// ACCOUNT UPDATE
// ================================================================================================

#[derive(Debug, PartialEq)]
pub struct AccountSummary {
    pub account_id: AccountId,
    pub account_commitment: Word,
    pub block_num: BlockNumber,
}

impl From<&AccountSummary> for proto::account::AccountSummary {
    fn from(update: &AccountSummary) -> Self {
        Self {
            account_id: Some(update.account_id.into()),
            account_commitment: Some(update.account_commitment.into()),
            block_num: update.block_num.as_u32(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct AccountInfo {
    pub summary: AccountSummary,
    pub details: Option<Account>,
}

impl From<&AccountInfo> for proto::account::AccountDetails {
    fn from(AccountInfo { summary, details }: &AccountInfo) -> Self {
        Self {
            summary: Some(summary.into()),
            details: details.as_ref().map(Serializable::to_bytes),
        }
    }
}

// ACCOUNT STORAGE HEADER
//================================================================================================

impl TryFrom<proto::account::AccountStorageHeader> for AccountStorageHeader {
    type Error = ConversionError;

    fn try_from(value: proto::account::AccountStorageHeader) -> Result<Self, Self::Error> {
        let proto::account::AccountStorageHeader { slots } = value;

        let slot_headers = slots
            .into_iter()
            .map(|slot| {
                let slot_name = StorageSlotName::new(slot.slot_name)?;
                let slot_type = storage_slot_type_from_raw(slot.slot_type)?;
                let commitment =
                    slot.commitment.ok_or(ConversionError::NotAValidFelt)?.try_into()?;
                Ok(StorageSlotHeader::new(slot_name, slot_type, commitment))
            })
            .collect::<Result<Vec<_>, ConversionError>>()?;

        Ok(AccountStorageHeader::new(slot_headers)?)
    }
}

// ACCOUNT REQUEST
// ================================================================================================

/// Represents a request for an account proof.
pub struct AccountRequest {
    pub account_id: AccountId,
    // If not present, the latest account proof references the latest available
    pub block_num: Option<BlockNumber>,
    pub details: Option<AccountDetailRequest>,
}

impl TryFrom<proto::rpc::AccountRequest> for AccountRequest {
    type Error = ConversionError;

    fn try_from(value: proto::rpc::AccountRequest) -> Result<Self, Self::Error> {
        let proto::rpc::AccountRequest { account_id, block_num, details } = value;

        let account_id = account_id
            .ok_or(proto::rpc::AccountRequest::missing_field(stringify!(account_id)))?
            .try_into()?;
        let block_num = block_num.map(Into::into);

        let details = details.map(TryFrom::try_from).transpose()?;

        Ok(AccountRequest { account_id, block_num, details })
    }
}

/// Represents a request for account details alongside specific storage data.
pub struct AccountDetailRequest {
    pub code_commitment: Option<Word>,
    pub asset_vault_commitment: Option<Word>,
    pub storage_requests: Vec<StorageMapRequest>,
}

impl TryFrom<proto::rpc::account_request::AccountDetailRequest> for AccountDetailRequest {
    type Error = ConversionError;

    fn try_from(
        value: proto::rpc::account_request::AccountDetailRequest,
    ) -> Result<Self, Self::Error> {
        let proto::rpc::account_request::AccountDetailRequest {
            code_commitment,
            asset_vault_commitment,
            storage_maps,
        } = value;

        let code_commitment = code_commitment.map(TryFrom::try_from).transpose()?;
        let asset_vault_commitment = asset_vault_commitment.map(TryFrom::try_from).transpose()?;
        let storage_requests = try_convert(storage_maps).collect::<Result<_, _>>()?;

        Ok(AccountDetailRequest {
            code_commitment,
            asset_vault_commitment,
            storage_requests,
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
        let proto::rpc::account_request::account_detail_request::StorageMapDetailRequest {
            slot_name,
            slot_data,
        } = value;

        let slot_name = StorageSlotName::new(slot_name)?;
        let slot_data = slot_data.ok_or(proto::rpc::account_request::account_detail_request::StorageMapDetailRequest::missing_field(stringify!(slot_data)))?.try_into()?;

        Ok(StorageMapRequest { slot_name, slot_data })
    }
}

/// Request of slot data values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotData {
    All,
    MapKeys(Vec<Word>),
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
                return Err(ConversionError::EnumDiscriminantOutOfRange);
            },
            ProtoSlotData::MapKeys(keys) => {
                let keys = try_convert(keys.map_keys).collect::<Result<Vec<_>, _>>()?;
                SlotData::MapKeys(keys)
            },
        })
    }
}

// ACCOUNT HEADER CONVERSIONS
//================================================================================================

impl TryFrom<proto::account::AccountHeader> for AccountHeader {
    type Error = ConversionError;

    fn try_from(value: proto::account::AccountHeader) -> Result<Self, Self::Error> {
        let proto::account::AccountHeader {
            account_id,
            vault_root,
            storage_commitment,
            code_commitment,
            nonce,
        } = value;

        let account_id = account_id
            .ok_or(proto::account::AccountHeader::missing_field(stringify!(account_id)))?
            .try_into()?;
        let vault_root = vault_root
            .ok_or(proto::account::AccountHeader::missing_field(stringify!(vault_root)))?
            .try_into()?;
        let storage_commitment = storage_commitment
            .ok_or(proto::account::AccountHeader::missing_field(stringify!(storage_commitment)))?
            .try_into()?;
        let code_commitment = code_commitment
            .ok_or(proto::account::AccountHeader::missing_field(stringify!(code_commitment)))?
            .try_into()?;
        let nonce = nonce.try_into().map_err(|_e| ConversionError::NotAValidFelt)?;

        Ok(AccountHeader::new(
            account_id,
            nonce,
            vault_root,
            storage_commitment,
            code_commitment,
        ))
    }
}

impl From<AccountHeader> for proto::account::AccountHeader {
    fn from(header: AccountHeader) -> Self {
        proto::account::AccountHeader {
            account_id: Some(header.id().into()),
            vault_root: Some(header.vault_root().into()),
            storage_commitment: Some(header.storage_commitment().into()),
            code_commitment: Some(header.code_commitment().into()),
            nonce: header.nonce().as_int(),
        }
    }
}

impl From<AccountStorageHeader> for proto::account::AccountStorageHeader {
    fn from(value: AccountStorageHeader) -> Self {
        let slots = value
            .slots()
            .map(|slot_header| proto::account::account_storage_header::StorageSlot {
                slot_name: slot_header.name().to_string(),
                slot_type: storage_slot_type_to_raw(slot_header.slot_type()),
                commitment: Some(proto::primitives::Digest::from(slot_header.value())),
            })
            .collect();

        Self { slots }
    }
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
    /// The vault has too many assets to return inline.
    /// Clients must use `SyncAccountVault` endpoint instead.
    LimitExceeded,

    /// The assets in the vault (up to `MAX_RETURN_ENTRIES`).
    Assets(Vec<Asset>),
}

impl AccountVaultDetails {
    /// Maximum number of vault entries that can be returned in a single response.
    /// Accounts with more assets will have `LimitExceeded` variant.
    pub const MAX_RETURN_ENTRIES: usize = 1000;

    pub fn new(vault: &AssetVault) -> Self {
        if vault.assets().nth(Self::MAX_RETURN_ENTRIES).is_some() {
            Self::LimitExceeded
        } else {
            Self::Assets(Vec::from_iter(vault.assets()))
        }
    }

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
            let parsed_assets =
                Result::<Vec<_>, ConversionError>::from_iter(assets.into_iter().map(|asset| {
                    let asset = asset
                        .asset
                        .ok_or(proto::primitives::Asset::missing_field(stringify!(asset)))?;
                    let asset = Word::try_from(asset)?;
                    Asset::try_from(asset).map_err(ConversionError::AssetError)
                }))?;
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
                assets: Vec::from_iter(assets.into_iter().map(|asset| proto::primitives::Asset {
                    asset: Some(proto::primitives::Digest::from(Word::from(asset))),
                })),
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
    /// The map has too many entries to return inline.
    /// Clients must use `SyncAccountStorageMaps` endpoint instead.
    LimitExceeded,

    /// All storage map entries (key-value pairs) without proofs.
    /// Used when all entries are requested for small maps.
    AllEntries(Vec<(Word, Word)>),

    /// Specific entries with their SMT proofs for client-side verification.
    /// Used when specific keys are requested from the storage map.
    EntriesWithProofs(Vec<SmtProof>),
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
    pub fn from_forest_entries(slot_name: StorageSlotName, entries: Vec<(Word, Word)>) -> Self {
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
    pub fn from_proofs(slot_name: StorageSlotName, proofs: Vec<SmtProof>) -> Self {
        if proofs.len() > Self::MAX_SMT_PROOF_ENTRIES {
            Self {
                slot_name,
                entries: StorageMapEntries::LimitExceeded,
            }
        } else {
            Self {
                slot_name,
                entries: StorageMapEntries::EntriesWithProofs(proofs),
            }
        }
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
            all_map_entries::StorageMapEntry,
            map_entries_with_proofs::StorageMapEntryWithProof,
            AllMapEntries,
            Entries as ProtoEntries,
            MapEntriesWithProofs,
        };

        let proto::rpc::account_storage_details::AccountStorageMapDetails {
            slot_name,
            too_many_entries,
            entries,
        } = value;

        let slot_name = StorageSlotName::new(slot_name)?;

        let entries = if too_many_entries {
            StorageMapEntries::LimitExceeded
        } else {
            match entries {
                None => {
                    return Err(
                        proto::rpc::account_storage_details::AccountStorageMapDetails::missing_field(
                            stringify!(entries),
                        ),
                    );
                },
                Some(ProtoEntries::AllEntries(AllMapEntries { entries })) => {
                    let entries = entries
                        .into_iter()
                        .map(|entry| {
                            let key = entry
                                .key
                                .ok_or(StorageMapEntry::missing_field(stringify!(key)))?
                                .try_into()?;
                            let value = entry
                                .value
                                .ok_or(StorageMapEntry::missing_field(stringify!(value)))?
                                .try_into()?;
                            Ok((key, value))
                        })
                        .collect::<Result<Vec<_>, ConversionError>>()?;
                    StorageMapEntries::AllEntries(entries)
                },
                Some(ProtoEntries::EntriesWithProofs(MapEntriesWithProofs { entries })) => {
                    let proofs = entries
                        .into_iter()
                        .map(|entry| {
                            let smt_opening = entry.proof.ok_or(
                                StorageMapEntryWithProof::missing_field(stringify!(proof)),
                            )?;
                            SmtProof::try_from(smt_opening)
                        })
                        .collect::<Result<Vec<_>, ConversionError>>()?;
                    StorageMapEntries::EntriesWithProofs(proofs)
                },
            }
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
            Entries as ProtoEntries,
            MapEntriesWithProofs,
        };

        let AccountStorageMapDetails { slot_name, entries } = value;

        let (too_many_entries, proto_entries) = match entries {
            StorageMapEntries::LimitExceeded => (true, None),
            StorageMapEntries::AllEntries(entries) => {
                let all = AllMapEntries {
                    entries: Vec::from_iter(entries.into_iter().map(|(key, value)| {
                        proto::rpc::account_storage_details::account_storage_map_details::all_map_entries::StorageMapEntry {
                            key: Some(key.into()),
                            value: Some(value.into()),
                        }
                    })),
                };
                (false, Some(ProtoEntries::AllEntries(all)))
            },
            StorageMapEntries::EntriesWithProofs(proofs) => {
                use miden_protocol::crypto::merkle::smt::SmtLeaf;

                let with_proofs = MapEntriesWithProofs {
                    entries: Vec::from_iter(proofs.into_iter().map(|proof| {
                        // Get key/value from the leaf before consuming the proof
                        let (key, value) = match proof.leaf() {
                            SmtLeaf::Empty(_) => {
                                (miden_protocol::EMPTY_WORD, miden_protocol::EMPTY_WORD)
                            },
                            SmtLeaf::Single((k, v)) => (*k, *v),
                            SmtLeaf::Multiple(entries) => entries.iter().next().map_or(
                                (miden_protocol::EMPTY_WORD, miden_protocol::EMPTY_WORD),
                                |(k, v)| (*k, *v),
                            ),
                        };
                        let smt_opening = proto::primitives::SmtOpening::from(proof);
                        proto::rpc::account_storage_details::account_storage_map_details::map_entries_with_proofs::StorageMapEntryWithProof {
                            key: Some(key.into()),
                            value: Some(value.into()),
                            proof: Some(smt_opening),
                        }
                    })),
                };
                (false, Some(ProtoEntries::EntriesWithProofs(with_proofs)))
            },
        };

        Self {
            slot_name: slot_name.to_string(),
            too_many_entries,
            entries: proto_entries,
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
        let proto::rpc::AccountStorageDetails { header, map_details } = value;

        let header = header
            .ok_or(proto::rpc::AccountStorageDetails::missing_field(stringify!(header)))?
            .try_into()?;

        let map_details = try_convert(map_details).collect::<Result<Vec<_>, _>>()?;

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

const fn storage_slot_type_from_raw(slot_type: u32) -> Result<StorageSlotType, ConversionError> {
    Ok(match slot_type {
        0 => StorageSlotType::Value,
        1 => StorageSlotType::Map,
        _ => return Err(ConversionError::EnumDiscriminantOutOfRange),
    })
}

const fn storage_slot_type_to_raw(slot_type: StorageSlotType) -> u32 {
    match slot_type {
        StorageSlotType::Value => 0,
        StorageSlotType::Map => 1,
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
        let proto::rpc::AccountResponse { block_num, witness, details } = value;

        let block_num = block_num
            .ok_or(proto::rpc::AccountResponse::missing_field(stringify!(block_num)))?
            .into();

        let witness = witness
            .ok_or(proto::rpc::AccountResponse::missing_field(stringify!(witness)))?
            .try_into()?;

        let details = details.map(TryFrom::try_from).transpose()?;

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
        let proto::rpc::account_response::AccountDetails {
            header,
            code,
            vault_details,
            storage_details,
        } = value;

        let account_header = header
            .ok_or(proto::rpc::account_response::AccountDetails::missing_field(stringify!(header)))?
            .try_into()?;

        let storage_details = storage_details
            .ok_or(proto::rpc::account_response::AccountDetails::missing_field(stringify!(
                storage_details
            )))?
            .try_into()?;

        let vault_details = vault_details
            .ok_or(proto::rpc::account_response::AccountDetails::missing_field(stringify!(
                vault_details
            )))?
            .try_into()?;
        let account_code = code;

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
        let code = account_code;
        let vault_details = Some(vault_details.into());

        Self {
            header,
            storage_details,
            code,
            vault_details,
        }
    }
}

// ACCOUNT WITNESS
// ================================================================================================

impl TryFrom<proto::account::AccountWitness> for AccountWitness {
    type Error = ConversionError;

    fn try_from(account_witness: proto::account::AccountWitness) -> Result<Self, Self::Error> {
        let witness_id = account_witness
            .witness_id
            .ok_or(proto::account::AccountWitness::missing_field(stringify!(witness_id)))?
            .try_into()?;
        let commitment = account_witness
            .commitment
            .ok_or(proto::account::AccountWitness::missing_field(stringify!(commitment)))?
            .try_into()?;
        let path = account_witness
            .path
            .ok_or(proto::account::AccountWitness::missing_field(stringify!(path)))?
            .try_into()?;

        AccountWitness::new(witness_id, commitment, path).map_err(|err| {
            ConversionError::deserialization_error(
                "AccountWitness",
                DeserializationError::InvalidValue(err.to_string()),
            )
        })
    }
}

impl From<AccountWitness> for proto::account::AccountWitness {
    fn from(witness: AccountWitness) -> Self {
        Self {
            account_id: Some(witness.id().into()),
            witness_id: Some(witness.id().into()),
            commitment: Some(witness.state_commitment().into()),
            path: Some(witness.into_proof().into_parts().0.into()),
        }
    }
}

// ACCOUNT WITNESS RECORD
// ================================================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountWitnessRecord {
    pub account_id: AccountId,
    pub witness: AccountWitness,
}

impl TryFrom<proto::account::AccountWitness> for AccountWitnessRecord {
    type Error = ConversionError;

    fn try_from(
        account_witness_record: proto::account::AccountWitness,
    ) -> Result<Self, Self::Error> {
        let witness_id = account_witness_record
            .witness_id
            .ok_or(proto::account::AccountWitness::missing_field(stringify!(witness_id)))?
            .try_into()?;
        let commitment = account_witness_record
            .commitment
            .ok_or(proto::account::AccountWitness::missing_field(stringify!(commitment)))?
            .try_into()?;
        let path: SparseMerklePath = account_witness_record
            .path
            .as_ref()
            .ok_or(proto::account::AccountWitness::missing_field(stringify!(path)))?
            .clone()
            .try_into()?;

        let witness = AccountWitness::new(witness_id, commitment, path).map_err(|err| {
            ConversionError::deserialization_error(
                "AccountWitness",
                DeserializationError::InvalidValue(err.to_string()),
            )
        })?;

        Ok(Self {
            account_id: account_witness_record
                .account_id
                .ok_or(proto::account::AccountWitness::missing_field(stringify!(account_id)))?
                .try_into()?,
            witness,
        })
    }
}

impl From<AccountWitnessRecord> for proto::account::AccountWitness {
    fn from(from: AccountWitnessRecord) -> Self {
        Self {
            account_id: Some(from.account_id.into()),
            witness_id: Some(from.witness.id().into()),
            commitment: Some(from.witness.state_commitment().into()),
            path: Some(from.witness.path().clone().into()),
        }
    }
}

// ACCOUNT STATE
// ================================================================================================

/// Information needed from the store to verify account in transaction.
#[derive(Debug)]
pub struct AccountState {
    /// Account ID
    pub account_id: AccountId,
    /// The account commitment in the store corresponding to tx's account ID
    pub account_commitment: Option<Word>,
}

impl Display for AccountState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{{ account_id: {}, account_commitment: {} }}",
            self.account_id,
            format_opt(self.account_commitment.as_ref()),
        ))
    }
}

impl TryFrom<proto::store::transaction_inputs::AccountTransactionInputRecord> for AccountState {
    type Error = ConversionError;

    fn try_from(
        from: proto::store::transaction_inputs::AccountTransactionInputRecord,
    ) -> Result<Self, Self::Error> {
        let account_id = from
            .account_id
            .ok_or(proto::store::transaction_inputs::AccountTransactionInputRecord::missing_field(
                stringify!(account_id),
            ))?
            .try_into()?;

        let account_commitment = from
            .account_commitment
            .ok_or(proto::store::transaction_inputs::AccountTransactionInputRecord::missing_field(
                stringify!(account_commitment),
            ))?
            .try_into()?;

        // If the commitment is equal to `Word::empty()`, it signifies that this is a new
        // account which is not yet present in the Store.
        let account_commitment = if account_commitment == Word::empty() {
            None
        } else {
            Some(account_commitment)
        };

        Ok(Self { account_id, account_commitment })
    }
}

impl From<AccountState> for proto::store::transaction_inputs::AccountTransactionInputRecord {
    fn from(from: AccountState) -> Self {
        Self {
            account_id: Some(from.account_id.into()),
            account_commitment: from.account_commitment.map(Into::into),
        }
    }
}

// ASSET
// ================================================================================================

impl TryFrom<proto::primitives::Asset> for Asset {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::Asset) -> Result<Self, Self::Error> {
        let inner = value.asset.ok_or(proto::primitives::Asset::missing_field("asset"))?;
        let word = Word::try_from(inner)?;

        Asset::try_from(word).map_err(ConversionError::AssetError)
    }
}

impl From<Asset> for proto::primitives::Asset {
    fn from(asset_from: Asset) -> Self {
        proto::primitives::Asset {
            asset: Some(Word::from(asset_from).into()),
        }
    }
}

// NETWORK ACCOUNT PREFIX
// ================================================================================================

pub type AccountPrefix = u32;

/// Newtype wrapper for network account IDs.
///
/// Provides type safety for accounts that are meant for network execution.
/// This wraps the full `AccountId` of a network account, typically extracted
/// from a `NetworkAccountTarget` attachment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct NetworkAccountId(AccountId);

impl std::fmt::Display for NetworkAccountId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl NetworkAccountId {
    /// Returns the inner `AccountId`.
    pub fn inner(&self) -> AccountId {
        self.0
    }

    /// Gets the 30-bit prefix of the account ID used for tag matching.
    pub fn prefix(&self) -> AccountPrefix {
        get_account_id_tag_prefix(self.0)
    }
}

impl TryFrom<AccountId> for NetworkAccountId {
    type Error = NetworkAccountError;

    fn try_from(id: AccountId) -> Result<Self, Self::Error> {
        if !id.is_network() {
            return Err(NetworkAccountError::NotNetworkAccount(id));
        }
        Ok(NetworkAccountId(id))
    }
}

impl TryFrom<&NoteAttachment> for NetworkAccountId {
    type Error = NetworkAccountError;

    fn try_from(attachment: &NoteAttachment) -> Result<Self, Self::Error> {
        let target = NetworkAccountTarget::try_from(attachment)
            .map_err(NetworkAccountError::InvalidAttachment)?;
        Ok(NetworkAccountId(target.target_id()))
    }
}

impl TryFrom<NoteAttachment> for NetworkAccountId {
    type Error = NetworkAccountError;

    fn try_from(attachment: NoteAttachment) -> Result<Self, Self::Error> {
        NetworkAccountId::try_from(&attachment)
    }
}

impl From<NetworkAccountId> for AccountId {
    fn from(value: NetworkAccountId) -> Self {
        value.inner()
    }
}

impl From<NetworkAccountId> for u32 {
    /// Returns the 30-bit prefix of the network account ID.
    /// This is used for note tag matching.
    fn from(value: NetworkAccountId) -> Self {
        value.prefix()
    }
}

#[derive(Debug, Error)]
pub enum NetworkAccountError {
    #[error("account ID {0} is not a valid network account ID")]
    NotNetworkAccount(AccountId),
    #[error("invalid network account attachment: {0}")]
    InvalidAttachment(#[source] NetworkAccountTargetError),
}

/// Gets the 30-bit prefix of the account ID.
fn get_account_id_tag_prefix(id: AccountId) -> AccountPrefix {
    (id.prefix().as_u64() >> 34) as AccountPrefix
}
