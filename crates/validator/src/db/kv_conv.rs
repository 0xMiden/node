use miden_protocol::transaction::{TransactionHeader, TransactionId};
use miden_protocol::utils::Deserializable;
use miden_tx::utils::{DeserializationError, Serializable};

pub trait ToKey {
    fn to_key(&self) -> fjall::UserKey;
}

pub trait ToValue: Sized {
    fn to_value(&self) -> fjall::UserValue;
    fn from_value(slice: fjall::Slice) -> Result<Self, DeserializationError>;
}

impl ToKey for TransactionId {
    fn to_key(&self) -> fjall::UserKey {
        fjall::UserKey::new(&self.as_bytes())
    }
}

impl ToValue for TransactionHeader {
    fn to_value(&self) -> fjall::UserValue {
        fjall::UserValue::new(&self.to_bytes())
    }

    fn from_value(slice: fjall::Slice) -> Result<Self, DeserializationError> {
        Self::read_from_bytes(&slice)
    }
}
