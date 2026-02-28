mod block_validation;
mod db;
mod server;
mod signers;
mod tx_validation;

pub use server::Validator;
pub use signers::ValidatorSigner;

// CONSTANTS
// =================================================================================================

/// The name of the validator component.
pub const COMPONENT: &str = "miden-validator";
