use miden_node_tracing::instrument;

#[instrument(rpc: root)]
fn root_sync() {}

#[instrument(rpc: root, ret)]
fn root_with_ret() -> u32 { 1 }

fn main() {
    root_sync();
    let _ = root_with_ret();
}
