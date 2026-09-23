use miden_node_tracing::{miden_instrument, miden_span_record};

struct UnapprovedAttribute;

#[miden_instrument]
fn records_unapproved_attribute() {
    miden_span_record!(transaction.id = UnapprovedAttribute);
}

fn main() {}
