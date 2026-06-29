mod server;
#[cfg(test)]
mod tests;

pub use server::{SequencerInternal, Rpc, RpcMode};

// CONSTANTS
// =================================================================================================
pub const COMPONENT: &str = "miden-rpc";
