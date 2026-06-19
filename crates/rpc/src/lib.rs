mod server;
#[cfg(test)]
mod tests;

pub use server::{PreAuthenticated, PreAuthenticatedSubmission, Rpc, RpcMode};

// CONSTANTS
// =================================================================================================
pub const COMPONENT: &str = "miden-rpc";
