use miden_protocol::Word;
use opentelemetry::Value;

use super::OpenTelemetryField;

/// Defines a [`Word`] wrapper field for use with OpenTelemetry tracing.
macro_rules! word_field {
    ($type:ident, $key:literal, $suffix:literal) => {
        pub(crate) struct $type(pub(crate) Word);

        impl OpenTelemetryField for $type {
            const DEFAULT_KEY: &'static str = $key;
            const DEFAULT_KEY_SUFFIX: &'static str = $suffix;

            fn to_otel_value(&self) -> Value {
                self.0.to_hex().into()
            }
        }
    };
}

word_field!(BlockCommitment, "block.commitment", "commitment");
word_field!(BlockSubCommitment, "block.sub_commitment", "sub_commitment");
word_field!(
    PreviousBlockCommitment,
    "block.previous_block_commitment",
    "previous_block_commitment"
);
word_field!(
    TransactionKernelCommitment,
    "block.commitments.transaction_kernel",
    "transaction_kernel"
);
word_field!(NullifierRoot, "block.roots.nullifier", "nullifier");
word_field!(AccountRoot, "block.roots.account", "account");
word_field!(ChainCommitment, "block.commitments.chain", "chain");
word_field!(NoteRoot, "block.roots.note", "note");
word_field!(TransactionCommitment, "block.commitments.transaction", "transaction");

pub(crate) struct BlockTimestamp(pub(crate) u32);

impl OpenTelemetryField for BlockTimestamp {
    const DEFAULT_KEY: &'static str = "block.timestamp";
    const DEFAULT_KEY_SUFFIX: &'static str = "timestamp";

    fn to_otel_value(&self) -> Value {
        i64::from(self.0).into()
    }
}

pub(crate) struct ProtocolVersion(pub(crate) u32);

impl OpenTelemetryField for ProtocolVersion {
    const DEFAULT_KEY: &'static str = "block.protocol.version";
    const DEFAULT_KEY_SUFFIX: &'static str = "version";

    fn to_otel_value(&self) -> Value {
        i64::from(self.0).into()
    }
}
