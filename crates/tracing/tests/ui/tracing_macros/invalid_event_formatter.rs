miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::info;

fn main() {
    info!("test.event", transaction.id = %"0x1234");
}
