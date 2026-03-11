//! Conversions between Miden domain types and database column types.

use miden_node_db::DatabaseError;
use miden_node_proto::domain::account::NetworkAccountId;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::{NoteScript, Nullifier};
use miden_protocol::transaction::TransactionId;
use miden_tx::utils::serde::{Deserializable, Serializable};

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

pub fn word_to_bytes(word: &Word) -> Vec<u8> {
    word.to_bytes()
}

pub fn note_script_to_bytes(script: &NoteScript) -> Vec<u8> {
    script.to_bytes()
}

pub fn note_script_from_bytes(bytes: &[u8]) -> Result<NoteScript, DatabaseError> {
    NoteScript::read_from_bytes(bytes).map_err(|e| DatabaseError::deserialization("note script", e))
}
