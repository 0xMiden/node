use miden_node_proto::generated::remote_prover as proto;
use miden_node_tracing::RecordAttribute;

/// Specifies the type of proof supported by the remote prover.
#[derive(Debug, Clone, Copy, PartialEq, clap::ValueEnum)]
pub enum ProofKind {
    Transaction,
    Batch,
    Block,
}

impl ProofKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ProofKind::Transaction => "transaction",
            ProofKind::Batch => "batch",
            ProofKind::Block => "block",
        }
    }
}

impl From<proto::ProofType> for ProofKind {
    fn from(value: proto::ProofType) -> Self {
        match value {
            proto::ProofType::Transaction => ProofKind::Transaction,
            proto::ProofType::Batch => ProofKind::Batch,
            proto::ProofType::Block => ProofKind::Block,
        }
    }
}

impl std::fmt::Display for ProofKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl RecordAttribute for ProofKind {
    const FIELD_NAMES: &'static [&'static str] = &["prover.kind", "request.kind"];

    fn record_attribute(&self) -> impl miden_node_tracing::Value + '_ {
        self.as_str()
    }
}
