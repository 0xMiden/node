miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::{instrument, miden_span_record};

struct UnapprovedAttribute;

#[instrument]
fn records_unapproved_attribute() {
    miden_span_record!(transaction.id = UnapprovedAttribute);
}

fn main() {}
