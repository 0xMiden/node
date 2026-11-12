//! Transaction-scoped log requests and persisted log collections.

use miden_protobuf::{ConversionResultExt, Verify};
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::{TransactionId, TransactionLog};

use crate::errors::ConversionError;
use crate::generated::miden::node::v1::{
    DecodedGetTransactionLogsRequest,
    GetTransactionLogsResponse as ProtoResponse,
};
use crate::generated::transaction::transaction_log_details::Visibility;
use crate::generated::transaction::{TransactionLogDetails, TransactionLogs};

/// Identifies a transaction under the account it executed against.
#[derive(Debug, Clone, Copy)]
pub struct GetTransactionLogsRequest {
    pub native_account_id: AccountId,
    pub transaction_id: TransactionId,
}

impl Verify for DecodedGetTransactionLogsRequest {
    type Verified = GetTransactionLogsRequest;
    type Error = ConversionError;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(GetTransactionLogsRequest {
            native_account_id: self.native_account_id.verify().context("native_account_id")?,
            transaction_id: self.transaction_id.verify().context("transaction_id")?,
        })
    }
}

/// Committed transaction position and logs, with the persisted collection commitment.
///
/// `None` denotes private logs. An empty public collection is `Some(Vec::new())`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetTransactionLogsResponse {
    pub transaction_id: TransactionId,
    pub native_account_id: AccountId,
    pub block_num: BlockNumber,
    pub transaction_index: u32,
    pub logs_commitment: Word,
    pub logs: Option<Vec<TransactionLog>>,
}

impl From<GetTransactionLogsResponse> for ProtoResponse {
    fn from(value: GetTransactionLogsResponse) -> Self {
        let visibility = match value.logs {
            Some(logs) => Visibility::Public(TransactionLogs {
                logs: logs.iter().map(Into::into).collect(),
            }),
            None => Visibility::Private(value.logs_commitment.into()),
        };
        Self {
            transaction_id: Some(value.transaction_id.into()),
            native_account_id: Some(value.native_account_id.into()),
            block_num: value.block_num.as_u32(),
            transaction_index: value.transaction_index,
            logs_commitment: Some(value.logs_commitment.into()),
            log_details: Some(TransactionLogDetails { visibility: Some(visibility) }),
        }
    }
}
