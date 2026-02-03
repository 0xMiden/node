use miden_protocol::transaction::TransactionId;
use miden_tx::utils::DeserializationError;

#[derive(thiserror::Error, Debug)]
pub enum DatabaseError {
    #[error("underlying database error")]
    ExecutionError(#[from] fjall::Error),
    #[error("failed to deserialize value bytes from the database")]
    DeserializationError(#[from] DeserializationError),
    #[error("the following transactions were not found to be validated {0:?}")]
    TransactionsNotFound(Vec<TransactionId>),
}
