miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::instrument;

#[instrument(fields(transaction.id = ?"0x1234"))]
fn selects_instrument_formatter() {}

fn main() {}
