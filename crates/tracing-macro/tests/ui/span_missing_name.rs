use miden_node_tracing_macro::info_span;

fn main() {
    let _span = info_span!(rpc);
}
