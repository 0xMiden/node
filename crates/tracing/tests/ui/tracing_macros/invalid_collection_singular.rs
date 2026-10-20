use std::fmt::{self, Display};

use miden_node_tracing::{RecordAttribute, miden_instrument, miden_span_record};

struct AccountId;

impl RecordAttribute for AccountId {
    const FIELD_NAMES: &'static [&'static str] = &["account.id"];

    fn record_attribute(&self) -> impl tracing::Value + '_ {
        "account-id"
    }
}

impl Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("account-id")
    }
}

#[miden_instrument]
fn records_collection_with_singular_field() {
    miden_span_record!(account.id = vec![AccountId]);
}

fn main() {
    records_collection_with_singular_field();
}
