use miden_node_tracing::{miden_instrument, miden_span_record};

#[miden_instrument]
fn records_count_with_wrong_type() {
    miden_span_record!(note.count = 1_u32);
}

fn main() {
    records_count_with_wrong_type();
}
