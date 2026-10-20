use miden_node_tracing::miden_instrument;

#[miden_instrument(
    fields(
        tx_id = "0x1234",
    ),
)]
fn records_invalid_field_name() {}

fn main() {
    records_invalid_field_name();
}
