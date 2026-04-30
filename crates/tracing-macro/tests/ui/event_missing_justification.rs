use miden_node_tracing_macro::event;

fn main() {
    let _event = event!(rpc, "missing justification", info);
}
