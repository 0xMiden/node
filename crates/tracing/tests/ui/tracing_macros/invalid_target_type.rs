miden_node_tracing::declare_targets! {
    default: 42_u32,
}

#[miden_node_tracing::instrument]
fn operation() {}

fn main() {}
