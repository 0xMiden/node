mod server;
#[cfg(test)]
mod tests;

pub use server::{NetworkTxAuth, Rpc, RpcMode};

// CONSTANTS
// =================================================================================================
pub const COMPONENT: &str = "miden-rpc";
