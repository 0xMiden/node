miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::{instrument, miden_span_record};

#[instrument]
fn records_invalid_annotation() {
    miden_span_record!(custom.attribute = 1 #[unchecked]);
}

fn main() {}
