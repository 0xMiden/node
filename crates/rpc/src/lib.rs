mod server;
#[cfg(test)]
mod tests;

pub use server::{BlockProducerBackend, EmbeddedRpc, Rpc};

// CONSTANTS
// =================================================================================================
pub const COMPONENT: &str = "miden-rpc";
