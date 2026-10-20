use miden_node_tracing::miden_span_record;

fn records_outside_miden_instrument() {
    let tx_id = "0x1234";

    miden_span_record!(
        transaction.id = tx_id
    );
}

fn main() {
    records_outside_miden_instrument();
}
