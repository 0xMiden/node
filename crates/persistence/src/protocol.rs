use std::sync::Arc;

use miden_objects::proto;
use miden_protobuf::{DecodeMessage, DecodeMessageExt};
use miden_protocol::MastForest;
use miden_protocol::account::{AccountCode, AccountProcedureRoot};
use miden_protocol::utils::serde::{Deserializable, Serializable};

use crate::{PersistenceError, ProtobufValue, generated};

macro_rules! codec {
    ($domain:ty, $message:ty, $build:ident, $encode:expr) => {
        impl ProtobufValue for $domain {
            type Message = $message;
            fn to_proto(&self) -> Self::Message {
                ($encode)(self)
            }
            fn from_proto(message: Self::Message) -> Result<Self, PersistenceError> {
                Ok(message.$build()?)
            }
        }
    };
}

codec!(
    miden_protocol::account::Account,
    proto::account::Account,
    decode_and_verify,
    |value: &miden_protocol::account::Account| value.into()
);
codec!(
    miden_protocol::account::AccountStorageHeader,
    proto::account::AccountStorageHeader,
    decode_and_verify,
    |value: &miden_protocol::account::AccountStorageHeader| value.into()
);
codec!(
    miden_protocol::asset::Asset,
    proto::asset::Asset,
    decode_and_verify,
    |value: &miden_protocol::asset::Asset| value.into()
);
codec!(
    miden_protocol::note::Note,
    proto::note::Note,
    decode_and_verify,
    |value: &miden_protocol::note::Note| value.into()
);
codec!(
    miden_protocol::note::NoteHeader,
    proto::note::NoteHeader,
    decode_and_verify,
    |value: &miden_protocol::note::NoteHeader| (*value).into()
);
codec!(
    miden_protocol::note::NoteDetails,
    proto::note::NoteDetails,
    decode_and_verify,
    |value: &miden_protocol::note::NoteDetails| value.into()
);
codec!(
    miden_protocol::note::NoteScript,
    proto::note::NoteScript,
    decode_and_verify,
    |value: &miden_protocol::note::NoteScript| value.into()
);
codec!(
    miden_protocol::note::NoteStorage,
    proto::note::NoteStorage,
    decode_and_verify,
    |value: &miden_protocol::note::NoteStorage| value.into()
);
codec!(
    miden_protocol::note::NoteAttachments,
    proto::note::NoteAttachments,
    decode_and_verify,
    |value: &miden_protocol::note::NoteAttachments| value.into()
);
codec!(
    miden_protocol::protocol_config::ProtocolConfig,
    proto::protocol_config::ProtocolConfig,
    decode_and_verify,
    |value: &miden_protocol::protocol_config::ProtocolConfig| value.into()
);
codec!(
    miden_protocol::crypto::merkle::SparseMerklePath,
    proto::primitives::SparseMerklePath,
    decode_and_verify,
    |value: &miden_protocol::crypto::merkle::SparseMerklePath| value.clone().into()
);
codec!(
    miden_protocol::crypto::merkle::mmr::PartialMmr,
    proto::primitives::PartialMmr,
    decode_and_verify,
    |value: &miden_protocol::crypto::merkle::mmr::PartialMmr| value.into()
);
codec!(
    miden_protocol::block::BlockHeader,
    proto::blockchain::BlockHeader,
    decode_and_build_unchecked,
    |value: &miden_protocol::block::BlockHeader| value.into()
);
codec!(
    miden_protocol::block::SignedBlock,
    proto::blockchain::SignedBlock,
    decode_and_build_unchecked,
    |value: &miden_protocol::block::SignedBlock| value.into()
);
codec!(
    miden_protocol::transaction::TransactionInputs,
    proto::transaction::TransactionInputs,
    decode_and_build_unchecked,
    |value: &miden_protocol::transaction::TransactionInputs| value.into()
);
codec!(
    miden_protocol::transaction::ProvenTransaction,
    proto::transaction::ProvenTransaction,
    decode_and_build_unchecked,
    |value: &miden_protocol::transaction::ProvenTransaction| value.into()
);

// The miden-objects protobuf conversion can omit MAST node hashes for untrusted validation. Stored
// code keeps these hashes so MastForest::read_from_bytes can restore it as trusted data.
impl ProtobufValue for AccountCode {
    type Message = generated::AccountCode;

    fn to_proto(&self) -> Self::Message {
        generated::AccountCode {
            mast: Some(generated::MastForest { encoded: self.mast().to_bytes() }),
            procedure_roots: self.procedure_roots().map(Into::into).collect(),
        }
    }

    fn from_proto(message: Self::Message) -> Result<Self, PersistenceError> {
        let mast = message.mast.ok_or_else(|| {
            miden_protobuf::ConversionError::missing_field::<generated::AccountCode>("mast")
        })?;
        let mast = Arc::new(MastForest::read_from_bytes(&mast.encoded)?);
        let roots = message
            .procedure_roots
            .into_iter()
            .map(|root| root.decode_fields().map(AccountProcedureRoot::from_raw))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AccountCode::from_parts(mast, roots)?)
    }
}
