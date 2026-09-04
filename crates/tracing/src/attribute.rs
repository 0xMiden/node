use std::fmt::{self, Display, Formatter};
use std::path::{Path, PathBuf};

use miden_protocol::Word;
use miden_protocol::account::{AccountId, AccountIdPrefix, StorageMapKey, StorageSlotName};
use miden_protocol::batch::BatchId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteId, Nullifier};
use miden_protocol::transaction::TransactionId;
use tracing::Value;

const BOOLEAN_FIELD_NAMES: &[&str] = &[
    "account.updated",
    "note.erased",
    "note.id_resolved",
    "panic",
    "request.include_mmr_proof",
    "request.include_proof",
    "rpc.authentication.configured",
];

const NUMBER_FIELD_NAMES: &[&str] = &[
    "account.id.length",
    "account.index",
    "asset.amount",
    "asset.balance",
    "batch.expiration_height",
    "batch.expires_at",
    "batch.reference_block.number",
    "batch.size",
    "block.from",
    "block.number",
    "block.protocol.version",
    "block.size",
    "block.timestamp",
    "block_range.from",
    "block_range.to",
    "counter.failures.consecutive",
    "counter.latency.timeout_ms",
    "counter.value.expected",
    "counter.value.observed",
    "counter.value.target",
    "current_client_block_height",
    "cutoff_block",
    "db.account_state_forest.size",
    "db.account_tree.size",
    "db.block_store.size",
    "db.nullifier_tree.size",
    "db.sqlite.connection_pool_size",
    "db.sqlite.size",
    "db.sqlite.wal.size",
    "dice_roll",
    "failure_rate",
    "inputs_size",
    "mempool.accounts",
    "mempool.batches.proposed",
    "mempool.batches.proven",
    "mempool.nullifiers",
    "mempool.output_notes",
    "mempool.transactions.unbatched",
    "mempool.transactions.uncommitted",
    "note.tag",
    "ntx_builder.max_concurrent_txs",
    "ntx_builder.max_cycles",
    "ntx_builder.tx_expiration_delta",
    "port",
    "pow.hash",
    "pow.nonce",
    "pow.target",
    "pow.target.leading_zero_bits",
    "prefix_len",
    "proof_size",
    "prover.capacity",
    "prover.port",
    "prover.proof_type.raw",
    "reference_block.number",
    "retry.attempt",
    "retry.delay_ms",
    "shutdown.grace_period_ms",
    "snapshot.block_num",
    "snapshot.lifetime_ms",
    "snapshot.superseded_for_ms",
    "snapshots.live",
    "subscription.idle_ms",
    "subscription.stall_timeout_ms",
    "sync.block_gap",
    "sync.ready_threshold",
    "sync.upstream_block",
    "timeout.ms",
    "tip.number",
    "tip.stale_duration_secs",
    "transaction.expiration_delta",
    "transaction.expires_at",
    "transaction.reference_block.number",
    "transaction.submitted_at",
    "worker.status.raw",
    "workers.active",
    "workers.capacity",
];

const STRING_FIELD_NAMES: &[&str] = &[
    "account.id",
    "account.storage.kind",
    "account.storage.map.entry.operation",
    "account.storage.operation",
    "asset.symbol",
    "batch.interval",
    "block.interval",
    "dependency.endpoint",
    "dependency.name",
    "genesis.source",
    "genesis.source.kind",
    "grpc.timeout",
    "internal.listen",
    "mempool.removal.reason",
    "network_monitor.listen",
    "node.role",
    "note.execution_cycles",
    "ntx_builder.endpoint",
    "ntx_builder.idle_timeout",
    "ntx_builder.listen",
    "operation.name",
    "path",
    "pow.challenge.prefix",
    "prover",
    "prover.kind",
    "prover.timeout",
    "request.kind",
    "rpc.endpoint",
    "rpc.listen",
    "rpc.timeout",
    "sequencer.endpoint",
    "service.name",
    "service.version",
    "shutdown.signal",
    "sync.block_source.endpoint",
    "task.name",
    "transaction.id",
    "transaction.input_notes",
    "transaction.output_notes",
    "tx_prover.endpoint",
    "tx_prover.timeout",
    "validator.admin_listen",
    "validator.endpoints",
    "validator.listen",
    "validator.signer",
    "worker.name",
];

/// Converts a value into its canonical tracing attribute representation.
///
/// Values passed to the Miden tracing span and event macros must implement this trait.
/// Implementations decide the allowed scalar field names, the attribute's primitive type, and its
/// formatting, allowing tracing macros to use one name and representation consistently at every
/// recording site. Collection implementations derive their field names by appending `s` to these
/// scalar names.
pub trait RecordAttribute {
    /// Scalar field names associated with this value's type.
    const FIELD_NAMES: &'static [&'static str];

    /// Whether the final component of each field name must have an `s` suffix.
    const PLURALIZE_FIELD_NAMES: bool = false;

    /// Returns the value that is passed to `tracing`.
    fn record_attribute(&self) -> impl Value + '_;
}

/// Returns whether `field_name` occurs in `field_names`.
///
/// This is public because it is referenced by the tracing proc macros. Callers should use the
/// macros rather than invoking it directly.
#[doc(hidden)]
pub const fn field_name_allowed(field_names: &[&str], field_name: &str, pluralize: bool) -> bool {
    let mut index = 0;
    while index < field_names.len() {
        let allowed = if pluralize {
            str_eq_with_s_suffix(field_names[index], field_name)
        } else {
            str_eq(field_names[index], field_name)
        };
        if allowed {
            return true;
        }
        index += 1;
    }
    false
}

const fn str_eq_with_s_suffix(singular: &str, plural: &str) -> bool {
    let singular = singular.as_bytes();
    let plural = plural.as_bytes();
    if plural.len() != singular.len() + 1 || plural[singular.len()] != b's' {
        return false;
    }

    let mut index = 0;
    while index < singular.len() {
        if singular[index] != plural[index] {
            return false;
        }
        index += 1;
    }
    true
}

const fn str_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }

    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Converts an approved attribute into a `tracing` value.
///
/// This is public because it is referenced by the tracing proc macros. Callers should use the
/// macros rather than invoking it directly.
#[doc(hidden)]
pub fn record_attribute<T: RecordAttribute + ?Sized>(value: &T) -> impl Value + '_ {
    value.record_attribute()
}

macro_rules! impl_scalar_attribute {
    ($field_names:expr; $($ty:ty),* $(,)?) => {
        $(
            impl RecordAttribute for $ty {
                const FIELD_NAMES: &'static [&'static str] = $field_names;

                fn record_attribute(&self) -> impl Value + '_ {
                    *self
                }
            }
        )*
    };
}

impl_scalar_attribute!(BOOLEAN_FIELD_NAMES; bool);
impl_scalar_attribute!(
    NUMBER_FIELD_NAMES;
    f32,
    f64,
    i8,
    i16,
    i32,
    i64,
    i128,
    isize,
    u8,
    u16,
    u64,
    u128,
    usize,
);
impl_scalar_attribute!(NUMBER_FIELD_NAMES; u32);

impl RecordAttribute for str {
    const FIELD_NAMES: &'static [&'static str] = STRING_FIELD_NAMES;

    fn record_attribute(&self) -> impl Value + '_ {
        self
    }
}

impl RecordAttribute for String {
    const FIELD_NAMES: &'static [&'static str] = <str as RecordAttribute>::FIELD_NAMES;

    fn record_attribute(&self) -> impl Value + '_ {
        self.as_str()
    }
}

impl<T: RecordAttribute + ?Sized> RecordAttribute for &T {
    const FIELD_NAMES: &'static [&'static str] = T::FIELD_NAMES;
    const PLURALIZE_FIELD_NAMES: bool = T::PLURALIZE_FIELD_NAMES;

    fn record_attribute(&self) -> impl Value + '_ {
        (*self).record_attribute()
    }
}

impl<T: RecordAttribute> RecordAttribute for Option<T> {
    const FIELD_NAMES: &'static [&'static str] = T::FIELD_NAMES;
    const PLURALIZE_FIELD_NAMES: bool = T::PLURALIZE_FIELD_NAMES;

    fn record_attribute(&self) -> impl Value + '_ {
        self.as_ref().map(RecordAttribute::record_attribute)
    }
}

impl RecordAttribute for Path {
    const FIELD_NAMES: &'static [&'static str] = &["data.directory", "genesis.file", "path"];

    fn record_attribute(&self) -> impl Value + '_ {
        tracing::field::display(self.display())
    }
}

impl RecordAttribute for PathBuf {
    const FIELD_NAMES: &'static [&'static str] = <Path as RecordAttribute>::FIELD_NAMES;

    fn record_attribute(&self) -> impl Value + '_ {
        self.as_path().record_attribute()
    }
}

impl RecordAttribute for BlockNumber {
    const FIELD_NAMES: &'static [&'static str] = &[
        "batch.expiration_height",
        "batch.expires_at",
        "batch.reference_block.number",
        "block.from",
        "block.number",
        "block_range.from",
        "block_range.to",
        "cutoff_block",
        "current_client_block_height",
        "reference_block.number",
        "snapshot.block_num",
        "sync.upstream_block",
        "tip.number",
        "transaction.expires_at",
        "transaction.reference_block.number",
        "transaction.submitted_at",
    ];

    fn record_attribute(&self) -> impl Value + '_ {
        self.as_u64()
    }
}

macro_rules! impl_display_attribute {
    ($ty:ty, $field_names:expr $(,)?) => {
        impl RecordAttribute for $ty {
            const FIELD_NAMES: &'static [&'static str] = $field_names;

            fn record_attribute(&self) -> impl Value + '_ {
                tracing::field::display(self)
            }
        }
    };
}

impl_display_attribute!(
    AccountId,
    &[
        "account.id",
        "counter.account.id.new",
        "counter.account.id.old",
        "note.sender",
        "wallet.account.id.new",
        "wallet.account.id.old",
    ],
);
impl_display_attribute!(AccountIdPrefix, &["account.id.network_prefix"]);
impl_display_attribute!(StorageMapKey, &["account.storage.map.key"]);
impl_display_attribute!(StorageSlotName, &["account.storage.slot"]);
impl_display_attribute!(BatchId, &["batch.id", "block.batch.id"]);
impl_display_attribute!(NoteId, &["note.id"]);
impl_display_attribute!(Nullifier, &["note.nullifier"]);
impl_display_attribute!(TransactionId, &["block.transaction.id", "transaction.id"]);
impl_display_attribute!(
    Word,
    &[
        "account.final_state.commitment",
        "account.initial_state.commitment",
        "account.storage.value",
        "batch.reference_block.commitment",
        "block.commitment",
        "block.commitments.account",
        "block.commitments.chain",
        "block.commitments.kernel",
        "block.commitments.note",
        "block.commitments.nullifier",
        "block.commitments.transaction",
        "block.prev_block_commitment",
        "block.sub_commitment",
        "genesis.commitment",
        "script.root",
        "transaction.reference_block.commitment",
    ],
);

/// Formats a slice as one string-valued tracing attribute.
///
/// This is not an OpenTelemetry array: `tracing::Value` has no array representation, so the `OTel`
/// tracing layer receives the formatted list as a string.
struct AttributeList<'a, T>(&'a [T]);

impl<T: Display> Display for AttributeList<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut values = self.0.iter();
        let Some(first) = values.next() else {
            return f.write_str("None");
        };

        write!(f, "[{first}")?;
        for value in values {
            write!(f, ", {value}")?;
        }
        f.write_str("]")
    }
}

impl<T: Display + RecordAttribute> RecordAttribute for [T] {
    const FIELD_NAMES: &'static [&'static str] = T::FIELD_NAMES;
    const PLURALIZE_FIELD_NAMES: bool = true;

    fn record_attribute(&self) -> impl Value + '_ {
        tracing::field::display(AttributeList(self))
    }
}

impl<T: Display + RecordAttribute, const N: usize> RecordAttribute for [T; N] {
    const FIELD_NAMES: &'static [&'static str] = T::FIELD_NAMES;
    const PLURALIZE_FIELD_NAMES: bool = true;

    fn record_attribute(&self) -> impl Value + '_ {
        self.as_slice().record_attribute()
    }
}

impl<T: Display + RecordAttribute> RecordAttribute for Vec<T> {
    const FIELD_NAMES: &'static [&'static str] = T::FIELD_NAMES;
    const PLURALIZE_FIELD_NAMES: bool = true;

    fn record_attribute(&self) -> impl Value + '_ {
        self.as_slice().record_attribute()
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::account::AccountId;

    use super::{AttributeList, RecordAttribute, field_name_allowed};

    #[test]
    fn lists_use_the_canonical_format() {
        assert_eq!(AttributeList::<u32>(&[]).to_string(), "None");
        assert_eq!(AttributeList(&[1, 2, 3]).to_string(), "[1, 2, 3]");
    }

    #[test]
    fn references_are_approved_when_the_referenced_type_is_approved() {
        fn assert_record_attribute(_: &impl RecordAttribute) {}

        let value = "attribute";
        assert_record_attribute(&value);
        assert_record_attribute(&&value);
        assert_record_attribute(&Some(value));
        assert_record_attribute(&None::<&str>);
    }

    #[test]
    fn field_names_are_specific_to_the_attribute_type() {
        assert!(field_name_allowed(
            AccountId::FIELD_NAMES,
            "account.id",
            AccountId::PLURALIZE_FIELD_NAMES,
        ));
        assert!(!field_name_allowed(
            AccountId::FIELD_NAMES,
            "account.ids",
            AccountId::PLURALIZE_FIELD_NAMES,
        ));
        assert!(field_name_allowed(
            <[AccountId]>::FIELD_NAMES,
            "account.ids",
            <[AccountId]>::PLURALIZE_FIELD_NAMES,
        ));
        assert!(!field_name_allowed(
            <[AccountId]>::FIELD_NAMES,
            "account.id",
            <[AccountId]>::PLURALIZE_FIELD_NAMES,
        ));
    }
}
