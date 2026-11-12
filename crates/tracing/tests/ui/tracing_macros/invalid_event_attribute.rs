miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::info;

struct UnapprovedAttribute;

fn main() {
    info!("test.event", transaction.id = UnapprovedAttribute);
}
