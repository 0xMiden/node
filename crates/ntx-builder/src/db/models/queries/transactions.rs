//! Transaction-related models.

use diesel::prelude::*;

use crate::db::schema;

// MODELS
// ================================================================================================

/// Row read from `inflight_transactions`.
///
/// Only includes columns we need; use `.select(InflightTransactionRow::as_select())` when querying.
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = schema::inflight_transactions)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct InflightTransactionRow {
    pub delta_account_id: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = schema::inflight_transactions)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct InflightTransactionInsert {
    pub transaction_id: Vec<u8>,
    pub delta_account_id: Option<Vec<u8>>,
}
