use serde::{Deserialize, Serialize};

use crate::generated as proto;

/// Specifies the type of proof supported by the remote prover.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ProofKind {
    Transaction,
    Batch,
    Block,
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
        match self {
            ProofKind::Transaction => write!(f, "transaction"),
            ProofKind::Batch => write!(f, "batch"),
            ProofKind::Block => write!(f, "block"),
        }
    }
}

impl miden_node_utils::tracing::ToValue for ProofKind {
    fn to_value(&self) -> opentelemetry::Value {
        self.to_string().into()
    }
}

impl std::str::FromStr for ProofKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "transaction" => Ok(ProofKind::Transaction),
            "batch" => Ok(ProofKind::Batch),
            "block" => Ok(ProofKind::Block),
            _ => Err(format!("Invalid proof type: {s}")),
        }
    }
}
