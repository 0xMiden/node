miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::{instrument, miden_span_record};

struct UnapprovedAttribute;

#[instrument]
fn records_unapproved_attribute() {
    miden_span_record!(custom.attribute = UnapprovedAttribute #[nonstandard]);
}

fn main() {}
