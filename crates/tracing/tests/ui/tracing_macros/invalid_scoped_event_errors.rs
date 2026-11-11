miden_node_tracing::declare_targets! {
    default: "miden::storage",
}

fn main() {
    miden_node_tracing::error!("test.event");
    miden_node_tracing::warn!(42_u32, "test.event");
}
