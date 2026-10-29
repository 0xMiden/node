#[miden_node_tracing::instrument_v2]
pub fn target() -> &'static str {
    tracing::Span::current().metadata().unwrap().target()
}

pub fn event() {
    miden_node_tracing::info_v2!("maintenance.event");
}
