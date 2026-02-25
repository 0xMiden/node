pub mod generated;
pub mod server;

/// Component identifier for structured logging and tracing.
pub const COMPONENT: &str = "miden-prover";

// Convenience re-exports for library consumers.
pub use server::RpcListener;
pub use server::proof_kind::ProofKind;
