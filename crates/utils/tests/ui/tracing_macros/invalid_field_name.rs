use miden_node_utils::tracing::{miden_instrument, miden_span_record};

#[miden_instrument(skip_all)]
fn records_invalid_field_name() {
    let tx_id = "0x1234";

    miden_span_record!(tx_id = %tx_id);
}

fn main() {
    records_invalid_field_name();
}
