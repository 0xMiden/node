mod block_proposal;

pub mod account;
pub mod block;
pub mod encryption;
mod limits;
pub mod proof_request;
pub mod protocol_config;
pub mod sign_block_request;
pub mod submission;

use miden_node_tracing::{RecordAttribute, Value};

impl RecordAttribute for crate::generated::rpc::FinalityLevel {
    const FIELD_NAMES: &'static [&'static str] = &["finality_level"];

    fn record_attribute(&self) -> impl Value + '_ {
        self.as_str_name()
    }
}
