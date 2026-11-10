miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::instrument;

#[instrument(skip(value))]
fn records_implicit_argument(value: u32) {
    let _ = value;
}

fn main() {
    records_implicit_argument(1);
}
