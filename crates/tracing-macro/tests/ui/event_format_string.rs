use miden_node_tracing_macro::event;

fn main() {
    let message = "block accepted";
    let _event = event!(
        rpc,
        message,
        info,
        justification = "events must use static names so they can be cataloged",
    );
}
