mod server;
#[cfg(test)]
mod tests;

pub use server::{Rpc, RpcMode, Trusted, TrustedSubmission};

// CONSTANTS
// =================================================================================================
pub const COMPONENT: &str = "miden-rpc";
