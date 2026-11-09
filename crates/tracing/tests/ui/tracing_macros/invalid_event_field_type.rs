miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::debug;

fn main() {
    debug!("invalid.field.type", account.id = 42_u32);
}
