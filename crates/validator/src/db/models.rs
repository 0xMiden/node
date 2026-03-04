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
    pub account_delta: Vec<u8>,
    pub input_notes: Vec<u8>,
    pub output_notes: Vec<u8>,
    pub initial_account_hash: Vec<u8>,
    pub final_account_hash: Vec<u8>,
    pub fee: Vec<u8>,
}

impl ValidatedTransactionRowInsert {
    pub fn new(tx: &ValidatedTransaction) -> Self {
        Self {
            id: tx.tx_id().to_bytes(),
            block_num: tx.block_num().to_raw_sql(),
            account_id: tx.account_id().to_bytes(),
            account_delta: tx.account_delta().to_bytes(),
            input_notes: tx.input_notes().to_bytes(),
            output_notes: tx.output_notes().to_bytes(),
            initial_account_hash: tx.initial_account_hash().to_bytes(),
            final_account_hash: tx.final_account_hash().to_bytes(),
            fee: tx.fee().amount().to_le_bytes().to_vec(),
        }
    }
}
