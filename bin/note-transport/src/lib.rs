//! Private note delivery over gRPC.

// Required by the generated instrumentation code.
extern crate miden_node_tracing as tracing;

pub mod db;
pub mod server;

pub const COMPONENT: &str = "miden-note-transport";
pub const LOG_TARGET: &str = "user::miden-note-transport";
