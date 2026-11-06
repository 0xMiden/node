miden_node_tracing::declare_targets! {
    default: "miden::storage",
}

fn main() {
    miden_node_tracing::info_v2!("test.event", tx_id = "0x1234");
    miden_node_tracing::debug_v2!("test.event", block.number = "invalid");
}
