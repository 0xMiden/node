//! Database query functions for the validator.
//!
//! Each query lives in its own directory holding the query function and the `.sql` file it reads
//! with `include_str!`. Every function takes a [`ReadTx`](miden_node_db::sqlite::ReadTx) or
//! [`WriteTx`](miden_node_db::sqlite::WriteTx) and is driven from a call site through a
//! [`ValidatorDbReader`](super::ValidatorDbReader) or [`ValidatorDbWriter`](super::ValidatorDbWriter)
//! method, which is the only way the rest of the crate reaches the database.

mod private_record_row;

mod count_signed_blocks;
pub use count_signed_blocks::count_signed_blocks;

mod count_validated_transactions;
pub use count_validated_transactions::count_validated_transactions;

mod delete_block;
pub use delete_block::delete_block;

mod find_unvalidated_transactions;
pub use find_unvalidated_transactions::find_unvalidated_transactions;

mod insert_block_header;
pub use insert_block_header::insert_block_header;

mod insert_validated_private_transaction;
pub use insert_validated_private_transaction::insert_validated_private_transaction;

mod link_block_transactions;
pub use link_block_transactions::link_block_transactions;

mod list_validated_transactions;
pub use list_validated_transactions::{
    ListTransactionsParams,
    ListedTransaction,
    list_validated_transactions,
};

mod load_all_transactions;
pub use load_all_transactions::load_all_transactions;

mod load_block_header;
pub use load_block_header::load_block_header;

mod load_chain_tip;
pub use load_chain_tip::load_chain_tip;

mod load_private_record;
pub use load_private_record::load_private_record;

mod load_private_records_by_key_epoch;
pub use load_private_records_by_key_epoch::load_private_records_by_key_epoch;

mod load_private_records_by_setup_context;
pub use load_private_records_by_setup_context::load_private_records_by_setup_context;

mod transaction_exists;
pub use transaction_exists::transaction_exists;

mod upsert_block_header;
pub use upsert_block_header::upsert_block_header;
