use std::fmt::{self, Display, Formatter};

use miden_node_tracing::{
    debug,
    error,
    info,
    RecordAttribute,
    miden_instrument,
    miden_span_record,
    trace,
    warn,
};

struct NotDebug;

struct ApprovedAttribute(&'static str);

impl RecordAttribute for ApprovedAttribute {
    const FIELD_NAMES: &'static [&'static str] = &["account.id", "transaction.id"];

    fn record_attribute(&self) -> impl tracing::Value + '_ {
        self.0
    }
}

impl std::fmt::Display for ApprovedAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

#[derive(Debug)]
struct ApprovedError;

impl Display for ApprovedError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("approved error")
    }
}

impl std::error::Error for ApprovedError {}

fn records_events() {
    let parent = tracing::info_span!("parent");

    trace!("trace.event");
    trace!(ApprovedError, "trace.error.event");
    debug!("debug.event", block.number = 1);
    debug!(ApprovedError, "debug.error.event");
    info!(target: "test", "info.event", transaction.id = ApprovedAttribute("0x1234"));
    info!(ApprovedError, "info.error.event");
    info!("nonstandard.event", custom.attribute = ApprovedAttribute("custom") #[nonstandard]);
    warn!(parent: &parent, "warn.event", account.updated = true);
    warn!(ApprovedError, "warn.error.event");
    error!(ApprovedError, target: "test", "error.event", block.number = 2);
    error!(anyhow::anyhow!("anyhow error"), "anyhow.error.event");
}
#[miden_instrument(
    target = "miden-node-tracing-test",
    name = "records_fields",
)]
fn records_fields() {
    let display_value = ApprovedAttribute("display");
    let list_value = vec![ApprovedAttribute("first"), ApprovedAttribute("second")];
    let plain_value = 7;

    miden_span_record!(
        transaction.id = display_value,
        transaction.ids = list_value,
        block.number = plain_value
    );
}

#[miden_instrument]
fn records_user_defined_attribute() {
    miden_span_record!(transaction.id = ApprovedAttribute("approved"));
}

#[miden_instrument]
fn records_with_default_instrument_args(not_debug: NotDebug) {
    let _ = not_debug;
    let value = 1;

    miden_span_record!(
        block.number = value
    );
}

#[miden_instrument(
    fields(
        transaction.id = ApprovedAttribute("0x1234"),
        account.updated,
    ),
)]
fn records_allowed_instrument_fields() {}

#[miden_instrument(
    fields(
        custom.attribute = ApprovedAttribute("explicit") #[nonstandard],
    ),
)]
fn records_nonstandard_instrument_field() {}

#[miden_instrument(
    fields(
        dice_roll = dice_roll,
    ),
)]
fn records_allowed_shorthand_instrument_field(dice_roll: f64) {}

#[miden_instrument]
fn records_same_field_more_than_once() {
    let value = 1;
    let updated = 2;

    miden_span_record!(
        block.number = value
    );
    miden_span_record!(
        block.number = updated
    );
}

#[miden_instrument]
fn records_nonstandard_delayed_field() {
    miden_span_record!(custom.attribute = ApprovedAttribute("delayed") #[nonstandard]);
}

#[miden_instrument]
fn records_allowed_canonical_fields() {
    let tx_id = ApprovedAttribute("0x1234");
    let account_id = ApprovedAttribute("0xabcd");
    let block_number = 12u32;
    let transaction_ids = [ApprovedAttribute("0x1"), ApprovedAttribute("0x2")];
    let transaction_count = transaction_ids.len();

    miden_span_record!(
        transaction.id = tx_id,
        account.id = account_id,
        account.updated = true,
        block.number = block_number,
        transaction.ids = transaction_ids,
        transaction.count = transaction_count,
        service.name = "node"
    );
}

#[miden_instrument(fields(unregistered.item.count = item_count))]
fn records_count_without_registration(item_count: usize) {}

fn main() {
    records_fields();
    records_user_defined_attribute();
    records_with_default_instrument_args(NotDebug);
    records_allowed_instrument_fields();
    records_nonstandard_instrument_field();
    records_allowed_shorthand_instrument_field(0.5);
    records_same_field_more_than_once();
    records_nonstandard_delayed_field();
    records_allowed_canonical_fields();
    records_count_without_registration(2);
}
