pub mod data_directory;
pub mod db;
mod server;
mod signers;
mod tx_validation;

pub use data_directory::DataDirectory;
pub use server::ValidatorServer;
pub use signers::{KmsSigner, ValidatorSigner};

// CONSTANTS
// =================================================================================================

/// The name of the validator component.
pub const COMPONENT: &str = "miden-validator";
