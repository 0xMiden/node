miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::debug;

fn main() {
    debug!(42_u32, "test.debug");
}
