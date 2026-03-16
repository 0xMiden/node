use miden_node_tracing::instrument;

#[instrument(rpc: err)]
fn foo() {}

fn main() {}
