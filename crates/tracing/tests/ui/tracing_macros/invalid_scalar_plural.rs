use miden_node_tracing::{RecordAttribute, miden_instrument, miden_span_record};

struct AccountId;

impl RecordAttribute for AccountId {
    const FIELD_NAMES: &'static [&'static str] = &["account.id"];

    fn record_attribute(&self) -> impl tracing::Value + '_ {
        "account-id"
    }
}

#[miden_instrument]
fn records_scalar_with_plural_field() {
    miden_span_record!(account.ids = AccountId);
}

fn main() {
    records_scalar_with_plural_field();
}
