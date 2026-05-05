//! Per-service card renderers. The dispatcher in [`super`] selects one of these based on the
//! [`crate::status::ServiceDetails`] variant carried by each [`crate::status::ServiceStatus`].

mod explorer;
mod faucet;
mod note_transport;
mod ntx;
mod remote_prover;
mod rpc;
mod validator;

pub(super) use explorer::render_explorer;
pub(super) use faucet::render_faucet_test;
pub(super) use note_transport::render_note_transport;
pub(super) use ntx::{render_ntx_increment, render_ntx_tracking};
pub(super) use remote_prover::render_remote_prover;
pub(super) use rpc::render_rpc_status;
pub(super) use validator::render_validator;
