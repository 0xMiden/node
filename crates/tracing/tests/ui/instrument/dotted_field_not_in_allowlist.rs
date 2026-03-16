use miden_node_tracing::instrument;

#[instrument(rpc: foo.bar.baz = %bar)]
fn foo() {}

fn main() {}
