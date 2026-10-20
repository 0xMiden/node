//! Method-specific codes in the first byte of gRPC status details.
//!
//! These values are part of the client API. Do not renumber or reuse them.

use miden_node_tracing::error;
use tonic::{Code, Status};

use crate::LOG_TARGET;

macro_rules! error_codes {
    ($name:ident { $($variant:ident = $value:literal),* $(,)? }) => {
        #[derive(Clone, Copy)]
        #[repr(u8)]
        pub(super) enum $name {
            $($variant = $value,)*
        }

        impl $name {
            pub(super) fn invalid_argument(self, message: impl ToString) -> Status {
                Status::with_details(
                    Code::InvalidArgument,
                    message.to_string(),
                    vec![self as u8].into(),
                )
            }
        }
    };
}

error_codes!(GetAccountErrorCode {
    DeserializationFailed = 1,
    AccountNotFound = 2,
    AccountNotPublic = 3,
    UnknownBlock = 4,
    BlockPruned = 5,
    StorageSlotNotFound = 6,
    StorageSlotNotMap = 7,
});

error_codes!(GetNotesByIdErrorCode { DeserializationFailed = 1 });
error_codes!(GetNoteScriptByRootErrorCode { DeserializationFailed = 1 });

error_codes!(SyncErrorCode { InvalidBlockRange = 1 });

error_codes!(SyncNotesErrorCode {
    FutureBlock = 2,
    DeserializationFailed = 3,
});

error_codes!(SyncNullifiersErrorCode {
    InvalidPrefixLength = 2,
    DeserializationFailed = 3,
    FutureBlock = 4,
});

error_codes!(SyncAccountVaultErrorCode {
    DeserializationFailed = 2,
    AccountNotPublic = 3,
    FutureBlock = 4,
});

error_codes!(SyncAccountStorageMapsErrorCode {
    DeserializationFailed = 2,
    AccountNotPublic = 4,
    FutureBlock = 5,
});

error_codes!(SyncTransactionsErrorCode {
    DeserializationFailed = 2,
    FutureBlock = 5,
});

error_codes!(SyncChainMmrErrorCode { FutureBlock = 2 });

pub(super) fn internal_error(message: impl Into<String>) -> Status {
    Status::with_details(Code::Internal, message, vec![0].into())
}

/// Logs `err` with its causes and returns an `INTERNAL` status with the error's own message.
///
/// The causes stay in the node's logs because they can describe node internals, such as database
/// errors, that a public client should not see.
pub(super) fn log_internal_error<E: std::error::Error + 'static>(err: &E) -> Status {
    error!(err, target: LOG_TARGET, "Internal error");
    internal_error(err.to_string())
}
