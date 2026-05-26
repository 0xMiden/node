mod server;
#[cfg(test)]
mod tests;

pub use server::{Rpc, RpcMode};

// CONSTANTS
// =================================================================================================
pub const COMPONENT: &str = "miden-rpc";
