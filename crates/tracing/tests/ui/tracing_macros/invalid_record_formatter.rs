use miden_node_tracing::{miden_instrument, miden_span_record};

#[miden_instrument]
fn selects_record_formatter() {
    miden_span_record!(transaction.id = %"0x1234");
}

fn main() {}
