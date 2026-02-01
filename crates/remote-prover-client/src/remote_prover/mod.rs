pub mod generated;

use crate::RemoteProverClientError;

#[cfg(feature = "tx-prover")]
mod tx_prover;
#[cfg(feature = "tx-prover")]
pub use tx_prover::RemoteTransactionProver;

#[cfg(feature = "batch-prover")]
mod batch_prover;
#[cfg(feature = "batch-prover")]
pub use batch_prover::RemoteBatchProver;

#[cfg(feature = "block-prover")]
mod block_prover;
#[cfg(feature = "block-prover")]
pub use block_prover::RemoteBlockProver;
