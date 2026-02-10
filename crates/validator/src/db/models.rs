use diesel::prelude::*;
use miden_node_store::SqlTypeConvert;
use miden_tx::utils::Serializable;

use crate::db::schema;
use crate::tx_validation::ValidatedTransactionInfo;

#[derive(Debug, Clone, PartialEq, Insertable)]
#[diesel(table_name = schema::validated_transactions)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct ValidatedTransactionInfoRowInsert {
    pub id: Vec<u8>,
    pub block_num: i64,
    pub account_id: Vec<u8>,
    pub info: Vec<u8>,
}

impl ValidatedTransactionInfoRowInsert {
    pub fn new(info: &ValidatedTransactionInfo) -> Self {
        Self {
            id: info.tx_id().to_bytes(),
            block_num: info.block_num().to_raw_sql(),
            account_id: info.account_id().to_bytes(),
            info: info.to_bytes(),
        }
    }
}
