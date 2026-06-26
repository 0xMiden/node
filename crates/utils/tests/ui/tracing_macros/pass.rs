use miden_node_utils::tracing::{miden_instrument, miden_span_record};

#[miden_instrument(target = "miden-node-utils-test", name = "records_fields", skip_all)]
fn records_fields() {
    let display_value = "display";
    let debug_value = vec![1, 2, 3];
    let plain_value = 7;

    miden_span_record!(
        transaction.id = %display_value,
        transactions.ids = ?debug_value,
        block.number = plain_value,
    );
}

#[miden_instrument]
fn records_with_default_instrument_args() {
    let value = 1;

    miden_span_record!(block.number = value);
}

#[miden_instrument(skip_all)]
fn records_same_field_more_than_once() {
    let value = 1;
    let updated = 2;

    miden_span_record!(block.number = value);
    miden_span_record!(block.number = updated);
}

#[miden_instrument(skip_all)]
fn records_allowed_canonical_fields() {
    let tx_id = "0x1234";
    let account_id = "0xabcd";
    let block_number = 12u32;
    let transaction_ids = ["0x1", "0x2"];
    let transaction_count = transaction_ids.len();

    miden_span_record!(
        transaction.id = %tx_id,
        account.id = %account_id,
        block.number = block_number,
        transactions.ids = ?transaction_ids,
        block.transactions.count = transaction_count,
    );
}

fn main() {
    records_fields();
    records_with_default_instrument_args();
    records_same_field_more_than_once();
    records_allowed_canonical_fields();
}
