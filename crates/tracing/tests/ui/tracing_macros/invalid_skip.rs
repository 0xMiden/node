use miden_node_tracing::miden_instrument;

#[miden_instrument(skip(value))]
fn records_implicit_argument(value: u32) {
    let _ = value;
}

fn main() {
    records_implicit_argument(1);
}
