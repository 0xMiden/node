use miden_node_tracing::instrument;

#[instrument(rpc: report)]
fn foo() {}

fn main() {}
