use miden_protocol::transaction::{TransactionHeader, TransactionId};
use miden_protocol::utils::Deserializable;
use miden_tx::utils::{DeserializationError, Serializable};

/// Trait for converting types into keys for the key-value store.
pub trait ToKey {
    fn to_key(&self) -> fjall::UserKey;
}

/// Trait for converting types from and into values for the key-value store.
pub trait ToValue: Sized {
    type Error;
    fn to_value(&self) -> fjall::UserValue;
    fn from_value(slice: fjall::Slice) -> Result<Self, Self::Error>;
}

impl ToKey for TransactionId {
    fn to_key(&self) -> fjall::UserKey {
        fjall::UserKey::new(&self.as_bytes())
    }
}

impl ToValue for TransactionHeader {
    type Error = DeserializationError;

    fn to_value(&self) -> fjall::UserValue {
        fjall::UserValue::new(&self.to_bytes())
    }

    fn from_value(slice: fjall::Slice) -> Result<Self, Self::Error> {
        Self::read_from_bytes(&slice)
    }
}
