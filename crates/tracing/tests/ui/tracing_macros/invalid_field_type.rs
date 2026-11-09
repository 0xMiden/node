miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::{instrument, miden_span_record};

#[instrument]
fn records_field_with_wrong_type() {
    miden_span_record!(account.id = 42_u32);
}

fn main() {
    records_field_with_wrong_type();
}
