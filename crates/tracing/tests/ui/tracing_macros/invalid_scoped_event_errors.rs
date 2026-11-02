macro_rules! tracing_target {
    () => {
        "miden::storage"
    };
}

fn main() {
    miden_node_tracing::error_v2!("test.event");
    miden_node_tracing::warn_v2!(42_u32, "test.event");
}
