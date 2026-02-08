use diesel::prelude::*;
use miden_protocol::transaction::{TransactionId, TransactionSummary};
use miden_tx::utils::Serializable;

use crate::db::schema;

#[derive(Debug, Clone, PartialEq, Insertable)]
#[diesel(table_name = schema::transactions)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct TransactionSummaryRowInsert {
    pub id: Vec<u8>,
    pub account_id: Vec<u8>,
    pub summary: Vec<u8>,
}

impl TransactionSummaryRowInsert {
    pub fn new(id: &TransactionId, summary: &TransactionSummary) -> Self {
        Self {
            id: id.to_bytes(),
            account_id: summary.account_delta().id().to_bytes(),
            summary: summary.to_bytes(),
        }
    }
}
