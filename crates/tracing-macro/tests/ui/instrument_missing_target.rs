use miden_node_tracing_macro::instrument;

#[instrument(name = "missing_target", level = info)]
fn missing_target() {}

fn main() {}
