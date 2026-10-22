//! Method-specific codes in the first byte of gRPC status details.
//!
//! These values are part of the client API. Do not renumber or reuse them.

use tonic::{Code, Status};

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

// Finite synchronization streams number their codes independently of the unary methods.

error_codes!(SyncAccountVaultV2ErrorCode {
    DeserializationFailed = 1,
    InvalidRange = 2,
    FutureTarget = 3,
    HistoryUnavailable = 4,
    AccountNotPublic = 6,
});

error_codes!(SyncAccountStorageMapsV2ErrorCode {
    DeserializationFailed = 1,
    InvalidRange = 2,
    FutureTarget = 3,
    HistoryUnavailable = 4,
    AccountNotPublic = 6,
});

error_codes!(SyncNotesV2ErrorCode {
    DeserializationFailed = 1,
    InvalidRange = 2,
    FutureTarget = 3,
});

error_codes!(SyncAccountCommitmentsErrorCode {
    DeserializationFailed = 1,
    InvalidRange = 2,
    FutureTarget = 3,
    HistoryUnavailable = 4,
});

error_codes!(GetTransactionsByIdErrorCode {
    DeserializationFailed = 1,
    MissingTarget = 2,
    FutureTarget = 3,
});

error_codes!(SyncTransactionsV2ErrorCode {
    DeserializationFailed = 1,
    InvalidRange = 2,
    FutureTarget = 3,
});

error_codes!(SyncNullifiersV2ErrorCode {
    DeserializationFailed = 1,
    InvalidRange = 2,
    FutureTarget = 3,
    InvalidPrefixLength = 6,
});
