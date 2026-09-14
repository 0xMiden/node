pub mod account;
pub mod block;
pub mod encryption;
pub mod proof_request;
pub mod protocol_config;
pub mod submission;

use miden_node_tracing::{RecordAttribute, Value};

impl RecordAttribute for crate::generated::rpc::FinalityLevel {
    const FIELD_NAMES: &'static [&'static str] = &["finality_level"];

    fn record_attribute(&self) -> impl Value + '_ {
        self.as_str_name()
    }
}

// UTILITIES
// ================================================================================================

pub fn convert<T, From, To>(from: T) -> impl Iterator<Item = To>
where
    T: IntoIterator<Item = From>,
    From: Into<To>,
{
    from.into_iter().map(Into::into)
}

pub fn try_convert<T, E, From, To>(from: T) -> impl Iterator<Item = Result<To, E>>
where
    T: IntoIterator<Item = From>,
    From: TryInto<To, Error = E>,
{
    from.into_iter().map(TryInto::try_into)
}
