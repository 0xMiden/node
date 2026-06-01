use miden_node_proto::generated::remote_prover as proto;

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

impl miden_node_utils::tracing::ToValue for ProofKind {
    fn to_value(&self) -> opentelemetry::Value {
        self.to_string().into()
    }
}
