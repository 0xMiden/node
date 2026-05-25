mod server;
#[cfg(test)]
mod tests;

pub use server::{Rpc, RpcSubmissionMode};

// CONSTANTS
// =================================================================================================
pub const COMPONENT: &str = "miden-rpc";
