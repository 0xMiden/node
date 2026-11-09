miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::{instrument, miden_span_record};

#[instrument]
fn selects_record_formatter() {
    miden_span_record!(transaction.id = %"0x1234");
}

fn main() {}
