//! Private note delivery over gRPC.

// Required by the generated instrumentation code.
extern crate miden_node_tracing as tracing;

miden_node_tracing::declare_targets! {
    default: "miden::rpc::server",
    "miden_note_transport::server::note_root" => "miden::rpc::client",
    "miden_note_transport::db" => "miden::storage::sqlite",
}

pub mod db;
pub mod server;

pub const COMPONENT: &str = "miden-note-transport";
