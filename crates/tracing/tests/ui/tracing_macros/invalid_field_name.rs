miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::{instrument, miden_span_record};

#[instrument]
fn records_invalid_field_name() {
    let tx_id = "0x1234";

    miden_span_record!(
        tx_id = tx_id
    );
}

fn main() {
    records_invalid_field_name();
}
