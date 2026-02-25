//! Conversions between Miden domain types and database column types.

use miden_node_db::DatabaseError;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_node_proto::domain::note::SingleTargetNetworkNote;
use miden_node_proto::generated as proto;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::{Note, NoteScript, Nullifier};
use miden_protocol::transaction::TransactionId;
use miden_tx::utils::{Deserializable, Serializable};
use prost::Message;

// SERIALIZATION (domain → DB)
// ================================================================================================

pub fn account_to_bytes(account: &Account) -> Vec<u8> {
    account.to_bytes()
}

pub fn block_header_to_bytes(header: &BlockHeader) -> Vec<u8> {
    header.to_bytes()
}

pub fn network_account_id_to_bytes(id: NetworkAccountId) -> Vec<u8> {
    id.inner().to_bytes()
}

pub fn transaction_id_to_bytes(id: &TransactionId) -> Vec<u8> {
    id.to_bytes()
}

pub fn nullifier_to_bytes(nullifier: &Nullifier) -> Vec<u8> {
    nullifier.to_bytes()
}

pub fn block_num_to_i64(block_num: BlockNumber) -> i64 {
    i64::from(block_num.as_u32())
}

#[expect(clippy::cast_sign_loss)]
pub fn block_num_from_i64(val: i64) -> BlockNumber {
    BlockNumber::from(val as u32)
}

/// Serializes a `SingleTargetNetworkNote` to bytes using its protobuf representation.
pub fn single_target_note_to_bytes(note: &SingleTargetNetworkNote) -> Vec<u8> {
    let proto_note: proto::note::NetworkNote = Note::from(note.clone()).into();
    proto_note.encode_to_vec()
}

// DESERIALIZATION (DB → domain)
// ================================================================================================

pub fn account_from_bytes(bytes: &[u8]) -> Result<Account, DatabaseError> {
    Account::read_from_bytes(bytes).map_err(|e| DatabaseError::deserialization("account", e))
}

pub fn account_id_from_bytes(bytes: &[u8]) -> Result<AccountId, DatabaseError> {
    AccountId::read_from_bytes(bytes).map_err(|e| DatabaseError::deserialization("account id", e))
}

pub fn network_account_id_from_bytes(bytes: &[u8]) -> Result<NetworkAccountId, DatabaseError> {
    let account_id = account_id_from_bytes(bytes)?;
    NetworkAccountId::try_from(account_id)
        .map_err(|e| DatabaseError::deserialization("network account id", e))
}

/// Deserializes a `SingleTargetNetworkNote` from its protobuf byte representation.
pub fn single_target_note_from_bytes(
    bytes: &[u8],
) -> Result<SingleTargetNetworkNote, DatabaseError> {
    let proto_note = proto::note::NetworkNote::decode(bytes)
        .map_err(|e| DatabaseError::deserialization("network note proto", e))?;
    SingleTargetNetworkNote::try_from(proto_note)
        .map_err(|e| DatabaseError::deserialization("network note conversion", e))
}

pub fn word_to_bytes(word: &Word) -> Vec<u8> {
    word.to_bytes()
}

pub fn note_script_to_bytes(script: &NoteScript) -> Vec<u8> {
    script.to_bytes()
}

pub fn note_script_from_bytes(bytes: &[u8]) -> Result<NoteScript, DatabaseError> {
    NoteScript::read_from_bytes(bytes).map_err(|e| DatabaseError::deserialization("note script", e))
}
