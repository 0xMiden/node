use miden_node_utils::tracing::{miden_instrument, miden_span_record};

#[miden_instrument(target = "miden-node-utils-test", name = "records_fields", skip_all)]
fn records_fields() {
    let display_value = "display";
    let debug_value = vec![1, 2, 3];
    let plain_value = 7;

    miden_span_record!(
        display.value = %display_value,
        debug.value = ?debug_value,
        plain.value = plain_value,
    );
}

#[miden_instrument]
fn records_with_default_instrument_args() {
    let value = 1;

    miden_span_record!(value = value);
}

#[miden_instrument(skip_all)]
fn records_same_field_more_than_once() {
    let value = 1;
    let updated = 2;

    miden_span_record!(value = value);
    miden_span_record!(value = updated);
}

fn main() {
    records_fields();
    records_with_default_instrument_args();
    records_same_field_more_than_once();
}
