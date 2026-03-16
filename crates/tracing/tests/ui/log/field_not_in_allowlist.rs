use miden_node_tracing::warn;

fn main() {
    warn!(foo = %x, "msg");
}
