miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::instrument;

struct UnapprovedAttribute;

#[instrument(fields(transaction.id = UnapprovedAttribute))]
fn records_unapproved_attribute() {}

fn main() {}
