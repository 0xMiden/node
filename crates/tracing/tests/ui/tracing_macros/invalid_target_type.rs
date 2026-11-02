macro_rules! tracing_target {
    () => {
        42_u32
    };
}

#[miden_node_tracing::instrument_v2]
fn operation() {}

fn main() {}
