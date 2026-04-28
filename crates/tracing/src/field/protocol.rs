use miden_protocol::account::AccountId;
use miden_protocol::batch::BatchId;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionId;
use opentelemetry::Value;

use super::OpenTelemetryField;

impl OpenTelemetryField for BlockNumber {
    const DEFAULT_KEY: &'static str = "block.number";
    const DEFAULT_KEY_SUFFIX: &'static str = "number";

    fn to_otel_value(&self) -> Value {
        i64::from(self.as_u32()).into()
    }
}

impl OpenTelemetryField for AccountId {
    const DEFAULT_KEY: &'static str = "account.id";
    const DEFAULT_KEY_SUFFIX: &'static str = "id";

    fn to_otel_value(&self) -> Value {
        self.to_hex().into()
    }
}

impl OpenTelemetryField for TransactionId {
    const DEFAULT_KEY: &'static str = "transaction.id";
    const DEFAULT_KEY_SUFFIX: &'static str = "id";

    fn to_otel_value(&self) -> Value {
        self.to_hex().into()
    }
}

impl OpenTelemetryField for BatchId {
    const DEFAULT_KEY: &'static str = "batch.id";
    const DEFAULT_KEY_SUFFIX: &'static str = "id";

    fn to_otel_value(&self) -> Value {
        self.to_hex().into()
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::account::AccountId;
    use miden_protocol::batch::BatchId;
    use miden_protocol::block::BlockNumber;
    use miden_protocol::transaction::TransactionId;
    use miden_protocol::{Felt, Word};

    use crate::OpenTelemetrySpanExt;
    use crate::test_utils::{assert_attribute, exported_span};

    #[test]
    fn block_number_records_with_default_key() {
        let block_number = BlockNumber::from(42);
        let span = exported_span(|span| span.record_field(&block_number));

        assert_attribute(&span, "block.number", 42_i64);
    }

    #[test]
    fn account_id_records_with_default_key() {
        let account_id = AccountId::from_hex("0x6d449e4034fadca075d1976fef7e38")
            .expect("test account ID should be valid");
        let span = exported_span(|span| span.record_field(&account_id));

        assert_attribute(&span, "account.id", account_id.to_hex());
    }

    #[test]
    fn transaction_id_records_with_default_key() {
        let transaction_id = test_transaction_id();
        let span = exported_span(|span| span.record_field(&transaction_id));

        assert_attribute(&span, "transaction.id", transaction_id.to_hex());
    }

    #[test]
    fn batch_id_records_with_default_key() {
        let account_id = AccountId::from_hex("0x6d449e4034fadca075d1976fef7e38")
            .expect("test account ID should be valid");
        let transaction_id = test_transaction_id();
        let batch_id = BatchId::from_ids([(transaction_id, account_id)]);
        let span = exported_span(|span| span.record_field(&batch_id));

        assert_attribute(&span, "batch.id", batch_id.to_hex());
    }

    fn test_transaction_id() -> TransactionId {
        TransactionId::from_raw(Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]))
    }
}
