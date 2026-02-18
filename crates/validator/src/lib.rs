mod block_validation;
mod db;
mod server;
mod tx_validation;

pub use server::Validator;

// CONSTANTS
// =================================================================================================

/// The name of the validator component.
pub const COMPONENT: &str = "miden-validator";
