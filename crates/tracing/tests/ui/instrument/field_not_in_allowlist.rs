use miden_node_tracing::instrument;

#[instrument(rpc: foo = bar)]
fn foo() {}

fn main() {}
