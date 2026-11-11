miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::instrument;

#[instrument(
    fields(
        tx_id = "0x1234",
    ),
)]
fn records_invalid_field_name() {}

fn main() {
    records_invalid_field_name();
}
