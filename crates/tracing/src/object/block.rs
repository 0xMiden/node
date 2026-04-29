use miden_protocol::Word;
use miden_protocol::block::BlockHeader;

use crate::field::block_header::{
    AccountRoot,
    BlockCommitment,
    BlockSubCommitment,
    BlockTimestamp,
    ChainCommitment,
    NoteRoot,
    NullifierRoot,
    PreviousBlockCommitment,
    ProtocolVersion,
    TransactionCommitment,
    TransactionKernelCommitment,
};
use crate::{OpenTelemetryObject, OpenTelemetryObjectRecorder};

impl OpenTelemetryObject for BlockHeader {
    const DEFAULT_KEY_PREFIX: &'static str = "block";

    fn record_attributes(&self, recorder: &mut OpenTelemetryObjectRecorder<'_>) {
        recorder.record_field(&self.block_num());
        recorder.record_field(&BlockCommitment(self.commitment()));
        recorder.record_field(&BlockSubCommitment(self.sub_commitment()));
        recorder.record_field(&PreviousBlockCommitment(self.prev_block_commitment()));
        recorder.record_field(&BlockTimestamp(self.timestamp()));
        recorder.record_object(&BlockProtocol { version: self.version() });
        recorder.record_object(&BlockCommitments {
            transaction_kernel: self.tx_kernel_commitment(),
            chain: self.chain_commitment(),
            transaction: self.tx_commitment(),
        });
        recorder.record_object(&BlockRoots {
            nullifier: self.nullifier_root(),
            account: self.account_root(),
            note: self.note_root(),
        });
    }
}

struct BlockProtocol {
    version: u32,
}

impl OpenTelemetryObject for BlockProtocol {
    const DEFAULT_KEY_PREFIX: &'static str = "protocol";

    fn record_attributes(&self, recorder: &mut OpenTelemetryObjectRecorder<'_>) {
        recorder.record_field(&ProtocolVersion(self.version));
    }
}

struct BlockCommitments {
    transaction_kernel: Word,
    chain: Word,
    transaction: Word,
}

impl OpenTelemetryObject for BlockCommitments {
    const DEFAULT_KEY_PREFIX: &'static str = "commitments";

    fn record_attributes(&self, recorder: &mut OpenTelemetryObjectRecorder<'_>) {
        recorder.record_field(&TransactionKernelCommitment(self.transaction_kernel));
        recorder.record_field(&ChainCommitment(self.chain));
        recorder.record_field(&TransactionCommitment(self.transaction));
    }
}

struct BlockRoots {
    nullifier: Word,
    account: Word,
    note: Word,
}

impl OpenTelemetryObject for BlockRoots {
    const DEFAULT_KEY_PREFIX: &'static str = "roots";

    fn record_attributes(&self, recorder: &mut OpenTelemetryObjectRecorder<'_>) {
        recorder.record_field(&NullifierRoot(self.nullifier));
        recorder.record_field(&AccountRoot(self.account));
        recorder.record_field(&NoteRoot(self.note));
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::block::BlockHeader;
    use miden_protocol::{Felt, Word};

    use crate::test_utils::{assert_attribute, exported_span};

    #[test]
    fn block_header_records_default_prefixed_attributes() {
        let header = test_block_header();
        let span = exported_span(|span| span.record_object(&header));

        assert_block_header_attributes(&span, "block", &header);
    }

    #[test]
    fn block_header_records_override_prefixed_attributes() {
        let header = test_block_header();
        let span = exported_span(|span| span.record_object_as(&header, "reference_block"));

        assert_block_header_attributes(&span, "reference_block", &header);
    }

    fn test_block_header() -> BlockHeader {
        BlockHeader::mock(42, Some(test_word(10)), Some(test_word(20)), &[], test_word(30))
    }

    fn test_word(seed: u64) -> Word {
        Word::new([Felt::new(seed), Felt::new(seed + 1), Felt::new(seed + 2), Felt::new(seed + 3)])
    }

    fn assert_block_header_attributes(
        span: &opentelemetry_sdk::trace::SpanData,
        prefix: &str,
        header: &BlockHeader,
    ) {
        assert_attribute(span, &format!("{prefix}.number"), i64::from(header.block_num().as_u32()));
        assert_attribute(span, &format!("{prefix}.commitment"), header.commitment().to_hex());
        assert_attribute(
            span,
            &format!("{prefix}.sub_commitment"),
            header.sub_commitment().to_hex(),
        );
        assert_attribute(
            span,
            &format!("{prefix}.previous_block_commitment"),
            header.prev_block_commitment().to_hex(),
        );
        assert_attribute(span, &format!("{prefix}.timestamp"), i64::from(header.timestamp()));
        assert_attribute(span, &format!("{prefix}.protocol.version"), i64::from(header.version()));
        assert_attribute(
            span,
            &format!("{prefix}.commitments.transaction_kernel"),
            header.tx_kernel_commitment().to_hex(),
        );
        assert_attribute(
            span,
            &format!("{prefix}.roots.nullifier"),
            header.nullifier_root().to_hex(),
        );
        assert_attribute(span, &format!("{prefix}.roots.account"), header.account_root().to_hex());
        assert_attribute(
            span,
            &format!("{prefix}.commitments.chain"),
            header.chain_commitment().to_hex(),
        );
        assert_attribute(span, &format!("{prefix}.roots.note"), header.note_root().to_hex());
        assert_attribute(
            span,
            &format!("{prefix}.commitments.transaction"),
            header.tx_commitment().to_hex(),
        );
    }
}
