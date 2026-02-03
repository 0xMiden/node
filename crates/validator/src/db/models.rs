use diesel::prelude::*;
use miden_protocol::transaction::TransactionHeader;
use miden_tx::utils::Serializable;

use crate::db::schema;

#[derive(Debug, Clone, PartialEq, Insertable)]
#[diesel(table_name = schema::transactions)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct TransactionSummaryRowInsert {
    pub transaction_id: Vec<u8>,
    pub data: Vec<u8>,
}

impl TransactionSummaryRowInsert {
    pub fn new(transaction_header: &TransactionHeader) -> Self {
        Self {
            transaction_id: transaction_header.id().to_bytes(),
            data: transaction_header.to_bytes(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Queryable, Selectable)]
#[diesel(table_name = schema::transactions)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct TransactionSummaryRowSelect {
    pub transaction_id: Vec<u8>,
    pub data: Vec<u8>,
}
