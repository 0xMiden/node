use miden_node_tracing::{miden_instrument, miden_span_record};

#[miden_instrument]
fn records_field_with_wrong_type() {
    miden_span_record!(account.id = 42_u32);
}

fn main() {
    records_field_with_wrong_type();
}
