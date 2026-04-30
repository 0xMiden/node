use miden_node_tracing_macro::info;

fn main() {
    let _event = info!(
        rpc,
        "fixed-level event",
        info,
        justification = "fixed-level event macros must not accept a level argument",
    );
}
