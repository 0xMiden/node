use miden_node_tracing::warn;

fn main() {
    warn!(rpc: foo = %x, "msg");
}
