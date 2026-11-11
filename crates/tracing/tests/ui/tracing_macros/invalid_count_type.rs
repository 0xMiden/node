miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::{instrument, miden_span_record};

#[instrument]
fn records_count_with_wrong_type() {
    miden_span_record!(note.count = 1_u32);
}

fn main() {
    records_count_with_wrong_type();
}
