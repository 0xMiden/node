miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::instrument;

#[instrument(skip_all)]
fn redundantly_skips_arguments(value: u32) {
    let _ = value;
}

fn main() {
    redundantly_skips_arguments(1);
}
