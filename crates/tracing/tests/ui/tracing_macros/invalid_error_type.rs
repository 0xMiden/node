miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::error;

fn main() {
    error!("not an error", "test.exception");
}
