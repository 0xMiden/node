use miden_node_tracing::miden_instrument;

#[miden_instrument(skip_all)]
fn redundantly_skips_arguments(value: u32) {
    let _ = value;
}

fn main() {
    redundantly_skips_arguments(1);
}
