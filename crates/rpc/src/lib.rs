mod server;
#[cfg(test)]
mod tests;

pub use server::{Rpc, RpcMode, SequencerInternal};

// CONSTANTS
// =================================================================================================
pub const COMPONENT: &str = "miden-rpc";
