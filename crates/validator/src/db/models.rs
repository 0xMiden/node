use diesel::prelude::*;
use miden_node_db::SqlTypeConvert;
use miden_tx::utils::Serializable;

use crate::db::schema;
use crate::tx_validation::ValidatedTransaction;

#[derive(Debug, Clone, PartialEq, Insertable)]
#[diesel(table_name = schema::validated_transactions)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct ValidatedTransactionRowInsert {
    pub id: Vec<u8>,
    pub block_num: i64,
    pub account_id: Vec<u8>,
    pub transaction: Vec<u8>,
}

impl ValidatedTransactionRowInsert {
    pub fn new(tx: &ValidatedTransaction) -> Self {
        Self {
            id: tx.tx_id().to_bytes(),
            block_num: tx.block_num().to_raw_sql(),
            account_id: tx.account_id().to_bytes(),
            transaction: tx.to_bytes(),
        }
    }
}
