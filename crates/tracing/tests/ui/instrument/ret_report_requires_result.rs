use miden_node_tracing::instrument;

#[instrument(rpc: ret, report)]
fn foo() {}

fn main() {}
